//! Capabilities - Fase 4 (v1 tabela flat com CDT).
//!
//! Modelo:
//! - Uma `CapTable` e um array fixo de slots indexados por `CapSlot` (u16).
//! - Cada slot contem um `Capability` ou esta vazio.
//! - Cada capability guarda ponteiros de CDT (Capability Derivation Tree)
//!   para parent, first_child, prev_sibling, next_sibling.
//! - Derivar (`copy`, `retype_untyped`) cria um filho na CDT.
//! - `revoke(slot)` apaga recursivamente TODOS os descendentes do slot,
//!   mantendo o proprio slot. E o primitivo de seguranca: nenhum acesso
//!   pode sobreviver a revoke da raiz.
//! - `delete(slot)` apaga um slot folha (sem filhos). Se tiver filhos,
//!   use `revoke` primeiro.
//!
//! Atenuacao: `copy(src, dst, rights)` exige `rights ⊆ src.rights`, ou seja,
//! derivacoes so podem diminuir direitos, nunca aumentar.
//!
//! Cross-CSpace (Phase 8): a CDT *dentro* de uma CSpace continua local.
//! Revogacao cross-CSpace e feita por uma tabela paralela de grants em
//! `crate::domain::GRANTS` (`cap_grant` registra; `revoke_granted`
//! varre e remove o destino). A CDT permanece `O(children)` por slot
//! sem atravessar fronteiras de dominio — KISS, e suficiente para o
//! protocolo de repossession.

#![forbid(unsafe_code)]

/// Numero maximo de slots por tabela. Define a capacidade total da CSpace.
pub const CAP_SLOTS: usize = 256;

/// Indice de slot. `NULL_SLOT` marca "sem slot" em links da CDT.
pub type CapSlot = u16;
pub const NULL_SLOT: CapSlot = u16::MAX;

/// Bitmask de direitos. `read`/`write`/`grant`/`revoke` sao independentes.
/// Direitos so podem ser atenuados em copias (nunca aumentados).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CapRights(pub u8);

impl CapRights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const GRANT: Self = Self(1 << 2);
    pub const ALL: Self = Self(0b0000_0111);

    #[inline]
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Referencia a um objeto do kernel.
///
/// `Untyped` e `Frame` carregam o phys diretamente (self-contained).
/// `Domain` carrega um `handle` u8 indexando `crate::domain::DOMAINS`
/// (objeto grande: CR3 + CSpace), isolando o lifecycle do objeto da
/// capability que o nomeia.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapObject {
    /// Regiao de memoria fisica nao-tipada `[base, base + size)`.
    ///
    /// Retype exige `(offset, size)` explicitos do chamador (LibOS):
    /// kernel so valida bounds e non-overlap com irmaos existentes.
    /// Mecanismo, nao politica — LibOS escolhe onde alocar (expose
    /// allocation, Engler-1995 §3).
    Untyped { base: u64, size: u64 },
    /// Frame fisico de 4 KiB em `phys`. Concedida a um dominio, da o direito
    /// de mapea-lo no proprio espaco de enderecamento via `domain::map`
    /// (Phase 7a.6). Os bits de proteção saem de `CapRights`: WRITE permite
    /// `Perm::UserRw`, sua ausencia restringe a `Perm::UserRx`.
    Frame { phys: u64 },
    /// Dominio ring 3 (Phase 7a.4). `handle` e indice em `domain::DOMAINS`.
    /// Cap concede direito de invocar o dominio via PCT (`domain_call`).
    Domain { handle: u8 },
}

/// Slot da tabela. `Empty` e o estado livre.
#[derive(Copy, Clone, Debug)]
pub enum CapEntry {
    Empty,
    Cap {
        object: CapObject,
        rights: CapRights,
        parent: CapSlot,
        first_child: CapSlot,
        prev_sibling: CapSlot,
        next_sibling: CapSlot,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CapError {
    SlotOutOfRange,
    SlotOccupied,
    SlotEmpty,
    InsufficientRights,
    HasChildren,
    WrongType,
    InvalidRetype,
}

/// CSpace (v1): array fixo de slots. Nao faz alocacao; caller escolhe slot.
pub struct CapTable {
    entries: [CapEntry; CAP_SLOTS],
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CapTable {
    pub const fn new() -> Self {
        Self { entries: [CapEntry::Empty; CAP_SLOTS] }
    }

    /// Cria um cap raiz (sem parent) em `slot`. Uso tipico: boot entrega
    /// ao kernel um Untyped cobrindo toda a memoria livre, inserido como raiz.
    pub fn insert_root(
        &mut self,
        slot: CapSlot,
        object: CapObject,
        rights: CapRights,
    ) -> Result<(), CapError> {
        self.check_range(slot)?;
        if !matches!(self.entries[slot as usize], CapEntry::Empty) {
            return Err(CapError::SlotOccupied);
        }
        self.entries[slot as usize] = CapEntry::Cap {
            object,
            rights,
            parent: NULL_SLOT,
            first_child: NULL_SLOT,
            prev_sibling: NULL_SLOT,
            next_sibling: NULL_SLOT,
        };
        Ok(())
    }

    /// Deriva `src` em `dst` com `rights` atenuados. Falha se `dst` ocupado
    /// ou se `rights` nao for subconjunto dos direitos de `src`.
    pub fn copy(
        &mut self,
        src: CapSlot,
        dst: CapSlot,
        rights: CapRights,
    ) -> Result<(), CapError> {
        self.check_range(src)?;
        self.check_range(dst)?;
        if src == dst {
            return Err(CapError::SlotOccupied);
        }
        if !matches!(self.entries[dst as usize], CapEntry::Empty) {
            return Err(CapError::SlotOccupied);
        }
        let (object, src_rights) = match self.entries[src as usize] {
            CapEntry::Cap { object, rights, .. } => (object, rights),
            CapEntry::Empty => return Err(CapError::SlotEmpty),
        };
        if !src_rights.contains(rights) {
            return Err(CapError::InsufficientRights);
        }
        self.link_child(src, dst, object, rights);
        Ok(())
    }

    /// Cria em `dst` um novo Untyped filho de `src` em
    /// `[base + offset, base + offset + size)`. LibOS escolhe
    /// `offset` e `size`; kernel so valida:
    ///
    ///   - `src` e Untyped;
    ///   - `size > 0`;
    ///   - `offset + size <= src.size` (dentro do pai);
    ///   - nao ha sobreposicao com irmaos ja criados.
    ///
    /// Exokernel puro: kernel expoe o recurso, LibOS decide
    /// a politica de alocacao (Engler-1995 §3: expose allocation).
    #[allow(unreachable_patterns)] // ramo WrongType ativa com novos CapObject
    pub fn retype_untyped(
        &mut self,
        src: CapSlot,
        dst: CapSlot,
        offset: u64,
        size: u64,
    ) -> Result<(), CapError> {
        self.check_range(src)?;
        self.check_range(dst)?;
        if src == dst {
            return Err(CapError::SlotOccupied);
        }
        if !matches!(self.entries[dst as usize], CapEntry::Empty) {
            return Err(CapError::SlotOccupied);
        }
        if size == 0 {
            return Err(CapError::InvalidRetype);
        }
        let (parent_base, parent_size, rights) = match self.entries[src as usize] {
            CapEntry::Cap {
                object: CapObject::Untyped { base, size },
                rights,
                ..
            } => (base, size, rights),
            CapEntry::Cap { .. } => return Err(CapError::WrongType),
            CapEntry::Empty => return Err(CapError::SlotEmpty),
        };
        // Bounds check com overflow-safe.
        let end = offset
            .checked_add(size)
            .ok_or(CapError::InvalidRetype)?;
        if end > parent_size {
            return Err(CapError::InvalidRetype);
        }
        let new_base = parent_base + offset;
        let new_end = new_base + size;
        // Non-overlap check: varre sibling chain de `src.first_child`.
        // Cada irmao Untyped ocupa [child.base, child.base+child.size);
        // rejeita se interseciona [new_base, new_end).
        let mut sib = match self.entries[src as usize] {
            CapEntry::Cap { first_child, .. } => first_child,
            _ => NULL_SLOT,
        };
        while sib != NULL_SLOT {
            let (s_base, s_size, s_next) = match self.entries[sib as usize] {
                CapEntry::Cap {
                    object: CapObject::Untyped { base, size },
                    next_sibling,
                    ..
                } => (base, size, next_sibling),
                CapEntry::Cap { next_sibling, .. } => (0, 0, next_sibling),
                CapEntry::Empty => break,
            };
            if s_size != 0 {
                let s_end = s_base + s_size;
                // Overlap sse max(bases) < min(ends).
                let max_base = if new_base > s_base { new_base } else { s_base };
                let min_end = if new_end < s_end { new_end } else { s_end };
                if max_base < min_end {
                    return Err(CapError::InvalidRetype);
                }
            }
            sib = s_next;
        }
        let child_object = CapObject::Untyped { base: new_base, size };
        self.link_child(src, dst, child_object, rights);
        Ok(())
    }

    /// Apaga um slot folha. Falha se tiver filhos; use `revoke` antes.
    pub fn delete(&mut self, slot: CapSlot) -> Result<(), CapError> {
        self.check_range(slot)?;
        match self.entries[slot as usize] {
            CapEntry::Cap { first_child, .. } if first_child != NULL_SLOT => {
                Err(CapError::HasChildren)
            }
            CapEntry::Cap { .. } => self.unlink_and_clear(slot),
            CapEntry::Empty => Err(CapError::SlotEmpty),
        }
    }

    /// Revoga recursivamente TODOS os descendentes de `slot`. O proprio slot
    /// permanece. E o primitivo de seguranca: apos `revoke(slot)`, nenhuma
    /// capability derivada de `slot` continua valida.
    pub fn revoke(&mut self, slot: CapSlot) -> Result<(), CapError> {
        self.check_range(slot)?;
        if matches!(self.entries[slot as usize], CapEntry::Empty) {
            return Err(CapError::SlotEmpty);
        }
        // Itera filhos ate nao restar nenhum. Cada chamada recursiva revoga
        // os netos e depois o delete_leaf apaga o filho, atualizando
        // first_child de `slot`. Profundidade maxima = CAP_SLOTS = 256.
        loop {
            let child = match self.entries[slot as usize] {
                CapEntry::Cap { first_child, .. } => first_child,
                CapEntry::Empty => return Ok(()),
            };
            if child == NULL_SLOT {
                break;
            }
            self.revoke(child)?;
            self.unlink_and_clear(child)?;
        }
        Ok(())
    }

    /// Leitura nao-mutavel de um slot. Util para validar invocacoes sem
    /// modificar a tabela.
    pub fn lookup(&self, slot: CapSlot) -> Result<(CapObject, CapRights), CapError> {
        self.check_range(slot)?;
        match self.entries[slot as usize] {
            CapEntry::Cap { object, rights, .. } => Ok((object, rights)),
            CapEntry::Empty => Err(CapError::SlotEmpty),
        }
    }

    // =================================================================
    // Internos
    // =================================================================

    fn check_range(&self, slot: CapSlot) -> Result<(), CapError> {
        if (slot as usize) < CAP_SLOTS {
            Ok(())
        } else {
            Err(CapError::SlotOutOfRange)
        }
    }

    /// Insere `dst` como primeiro filho de `parent` na CDT. `dst` deve
    /// estar vazio. Atualiza o sibling-chain de `parent`.
    fn link_child(
        &mut self,
        parent: CapSlot,
        dst: CapSlot,
        object: CapObject,
        rights: CapRights,
    ) {
        let old_first = match self.entries[parent as usize] {
            CapEntry::Cap { first_child, .. } => first_child,
            CapEntry::Empty => NULL_SLOT, // nao deveria acontecer; validado antes
        };
        self.entries[dst as usize] = CapEntry::Cap {
            object,
            rights,
            parent,
            first_child: NULL_SLOT,
            prev_sibling: NULL_SLOT,
            next_sibling: old_first,
        };
        if let CapEntry::Cap { first_child, .. } = &mut self.entries[parent as usize] {
            *first_child = dst;
        }
        if old_first != NULL_SLOT {
            if let CapEntry::Cap { prev_sibling, .. } = &mut self.entries[old_first as usize] {
                *prev_sibling = dst;
            }
        }
    }

    /// Remove `slot` do sibling-chain do parent e limpa o slot. Assume que
    /// `slot` nao tem filhos (senao vira dangling).
    fn unlink_and_clear(&mut self, slot: CapSlot) -> Result<(), CapError> {
        let (parent, prev, next) = match self.entries[slot as usize] {
            CapEntry::Cap { parent, prev_sibling, next_sibling, first_child, .. } => {
                debug_assert_eq!(first_child, NULL_SLOT);
                (parent, prev_sibling, next_sibling)
            }
            CapEntry::Empty => return Err(CapError::SlotEmpty),
        };
        // Desliga da lista de siblings.
        if prev != NULL_SLOT {
            if let CapEntry::Cap { next_sibling, .. } = &mut self.entries[prev as usize] {
                *next_sibling = next;
            }
        } else if parent != NULL_SLOT {
            // Era o primeiro filho; atualiza first_child do parent.
            if let CapEntry::Cap { first_child, .. } = &mut self.entries[parent as usize] {
                *first_child = next;
            }
        }
        if next != NULL_SLOT {
            if let CapEntry::Cap { prev_sibling, .. } = &mut self.entries[next as usize] {
                *prev_sibling = prev;
            }
        }
        self.entries[slot as usize] = CapEntry::Empty;
        Ok(())
    }
}

// =====================================================================
// Testes host
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_untyped(base: u64, size: u64) -> CapObject {
        CapObject::Untyped { base, size }
    }

    #[test]
    fn insert_root_ocupa_slot() {
        let mut t = CapTable::new();
        assert!(t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).is_ok());
        assert_eq!(t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL),
                   Err(CapError::SlotOccupied));
    }

    #[test]
    fn insert_root_fora_de_range() {
        let mut t = CapTable::new();
        assert_eq!(
            t.insert_root(CAP_SLOTS as CapSlot, mk_untyped(0, 4096), CapRights::ALL),
            Err(CapError::SlotOutOfRange)
        );
    }

    #[test]
    fn copy_atenua_direitos() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap();
        let (_, r) = t.lookup(1).unwrap();
        assert_eq!(r, CapRights::READ);
    }

    #[test]
    fn copy_rejeita_direitos_excedentes() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::READ).unwrap();
        assert_eq!(
            t.copy(0, 1, CapRights::ALL),
            Err(CapError::InsufficientRights)
        );
    }

    #[test]
    fn delete_com_filhos_falha() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap();
        assert_eq!(t.delete(0), Err(CapError::HasChildren));
    }

    #[test]
    fn delete_folha_limpa_slot() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap();
        t.delete(1).unwrap();
        assert_eq!(t.lookup(1), Err(CapError::SlotEmpty));
        // Parent continua valido, agora sem filhos.
        assert!(t.delete(0).is_ok());
    }

    #[test]
    fn revoke_apaga_todos_descendentes_mantem_raiz() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 8192), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap();
        t.copy(0, 2, CapRights::READ).unwrap();
        t.copy(1, 3, CapRights::READ).unwrap();
        t.copy(3, 4, CapRights::READ).unwrap();
        t.revoke(0).unwrap();
        assert!(t.lookup(0).is_ok(), "raiz deve sobreviver");
        for s in [1u16, 2, 3, 4] {
            assert_eq!(t.lookup(s), Err(CapError::SlotEmpty), "slot {} deveria estar vazio", s);
        }
    }

    #[test]
    fn revoke_em_subarvore_nao_apaga_irmaos() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 8192), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap(); // filho 1
        t.copy(0, 2, CapRights::READ).unwrap(); // filho 2
        t.copy(1, 3, CapRights::READ).unwrap(); // neto de 1
        t.revoke(1).unwrap();
        assert!(t.lookup(1).is_ok(), "alvo de revoke fica");
        assert!(t.lookup(2).is_ok(), "irmao nao afetado");
        assert_eq!(t.lookup(3), Err(CapError::SlotEmpty), "neto revogado");
    }

    #[test]
    fn retype_respeita_offset_do_libos() {
        // LibOS escolhe offset=0: filho fica em parent.base.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0, 0x1000).unwrap();
        match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, size } => {
                assert_eq!(base, 0x1000);
                assert_eq!(size, 0x1000);
            }
            _ => unreachable!("teste so cria Untyped"),
        }
    }

    #[test]
    fn retype_irmaos_nao_aliasam_com_offsets_explicitos() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x0000, 0x1000).unwrap(); // [0x1000,0x2000)
        t.retype_untyped(0, 2, 0x1000, 0x1000).unwrap(); // [0x2000,0x3000)
        let b1 = match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, .. } => base,
            _ => unreachable!("teste so cria Untyped"),
        };
        let b2 = match t.lookup(2).unwrap().0 {
            CapObject::Untyped { base, .. } => base,
            _ => unreachable!("teste so cria Untyped"),
        };
        assert_eq!(b1, 0x1000);
        assert_eq!(b2, 0x2000);
    }

    #[test]
    fn retype_rejeita_overlap_entre_irmaos() {
        // LibOS maliciosa tenta criar filho sobre regiao ja alocada.
        // Kernel DEVE rejeitar para nao permitir alias nao-rastreado.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x0000, 0x2000).unwrap(); // [0x1000,0x3000)
        assert_eq!(
            t.retype_untyped(0, 2, 0x1000, 0x1000), // [0x2000,0x3000) overlap
            Err(CapError::InvalidRetype)
        );
        assert_eq!(
            t.retype_untyped(0, 2, 0x0800, 0x1000), // [0x1800,0x2800) overlap
            Err(CapError::InvalidRetype)
        );
        // Offset logo apos o irmao funciona (bordas tocam, nao overlap).
        t.retype_untyped(0, 2, 0x2000, 0x1000).unwrap(); // [0x3000,0x4000)
    }

    #[test]
    fn retype_estoura_parent_size() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x2000), CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, 0x1800, 0x1000),
            Err(CapError::InvalidRetype),
            "offset+size > parent.size"
        );
    }

    #[test]
    fn retype_zero_size_rejeitado() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, 0, 0),
            Err(CapError::InvalidRetype)
        );
    }

    #[test]
    fn retype_offset_overflow_rejeitado() {
        // Defesa contra overflow em offset+size.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, u64::MAX, 1),
            Err(CapError::InvalidRetype)
        );
    }

    #[test]
    fn revoke_libera_regiao_para_novo_retype() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x0000, 0x2000).unwrap();
        t.retype_untyped(0, 2, 0x2000, 0x1000).unwrap();
        t.revoke(0).unwrap();
        // Filhos sumiram; a regiao toda volta a ser retypeable.
        t.retype_untyped(0, 1, 0, 0x1000).unwrap();
        match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, .. } => assert_eq!(base, 0x1000),
            _ => unreachable!("teste so cria Untyped"),
        }
    }

    #[test]
    fn retype_em_nao_untyped_rejeitado() {
        let mut t = CapTable::new();
        t.insert_root(0, CapObject::Frame { phys: 0x1000 }, CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, 0, 0x1000),
            Err(CapError::WrongType),
            "retype so funciona em Untyped"
        );
    }

    #[test]
    fn revoke_profunda_nao_estoura_stack() {
        // Cadeia linear de 64 capabilities: 0 -> 1 -> 2 -> ... -> 63.
        // Exercita recursao em profundidade; se mudarmos para iterativo,
        // este teste continua servindo como sanidade de linearizacao.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 65536), CapRights::ALL).unwrap();
        for i in 1..64u16 {
            t.copy(i - 1, i, CapRights::ALL).unwrap();
        }
        t.revoke(0).unwrap();
        for i in 1..64u16 {
            assert_eq!(t.lookup(i), Err(CapError::SlotEmpty));
        }
    }

    #[test]
    fn lookup_fora_de_range() {
        let t = CapTable::new();
        assert_eq!(t.lookup(CAP_SLOTS as CapSlot), Err(CapError::SlotOutOfRange));
    }

    #[test]
    fn rights_atenuacao_transitiva() {
        // src(ALL) -> a(READ|WRITE) -> b(READ) - ok
        // tentar derivar b com WRITE a partir de a falharia? Sim: a nao tem
        // WRITE se atribuimos so READ. Verifica que a atenuacao acumula.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights(CapRights::READ.0 | CapRights::WRITE.0)).unwrap();
        t.copy(1, 2, CapRights::READ).unwrap();
        assert_eq!(
            t.copy(2, 3, CapRights::WRITE),
            Err(CapError::InsufficientRights)
        );
    }

    // ---- Phase 8: testes adversariais ----

    #[test]
    fn copy_de_slot_vazio_falha() {
        let mut t = CapTable::new();
        assert_eq!(
            t.copy(0, 1, CapRights::READ),
            Err(CapError::SlotEmpty)
        );
    }

    #[test]
    fn copy_src_igual_dst_rejeitado() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        // Aliasing src=dst e malicioso (cria loop na CDT). A API
        // rejeita com SlotOccupied (semantica conservadora).
        assert_eq!(
            t.copy(0, 0, CapRights::READ),
            Err(CapError::SlotOccupied)
        );
    }

    #[test]
    fn revoke_em_slot_vazio_falha() {
        let mut t = CapTable::new();
        assert_eq!(t.revoke(0), Err(CapError::SlotEmpty));
    }

    #[test]
    fn revoke_dupla_e_idempotente_apos_primeira() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.copy(0, 1, CapRights::READ).unwrap();
        t.revoke(0).unwrap();
        // Apos primeiro revoke, raiz nao tem mais filhos. Segundo
        // revoke e no-op (loop sai imediatamente).
        assert!(t.revoke(0).is_ok());
        assert!(t.lookup(0).is_ok());
    }

    #[test]
    fn delete_fora_de_range() {
        let mut t = CapTable::new();
        assert_eq!(
            t.delete(CAP_SLOTS as CapSlot),
            Err(CapError::SlotOutOfRange)
        );
    }

    #[test]
    fn insert_frame_e_lookup() {
        let mut t = CapTable::new();
        t.insert_root(0, CapObject::Frame { phys: 0xdead_b000 }, CapRights::READ)
            .unwrap();
        let (obj, r) = t.lookup(0).unwrap();
        assert_eq!(obj, CapObject::Frame { phys: 0xdead_b000 });
        assert_eq!(r, CapRights::READ);
    }

    #[test]
    fn insert_domain_e_lookup() {
        let mut t = CapTable::new();
        t.insert_root(0, CapObject::Domain { handle: 7 }, CapRights::ALL)
            .unwrap();
        match t.lookup(0).unwrap().0 {
            CapObject::Domain { handle } => assert_eq!(handle, 7),
            _ => panic!("esperava Domain"),
        }
    }

    #[test]
    fn rights_contains_propriedades() {
        // Reflexivo
        assert!(CapRights::ALL.contains(CapRights::ALL));
        assert!(CapRights::READ.contains(CapRights::READ));
        // NONE e subset de qualquer um
        assert!(CapRights::ALL.contains(CapRights::NONE));
        assert!(CapRights::NONE.contains(CapRights::NONE));
        // ALL contem cada direito individual
        assert!(CapRights::ALL.contains(CapRights::READ));
        assert!(CapRights::ALL.contains(CapRights::WRITE));
        assert!(CapRights::ALL.contains(CapRights::GRANT));
        // Direitos individuais nao contem outros
        assert!(!CapRights::READ.contains(CapRights::WRITE));
        assert!(!CapRights::READ.contains(CapRights::ALL));
    }

    #[test]
    fn copy_em_slot_ocupado_falha() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 4096), CapRights::ALL).unwrap();
        t.insert_root(1, mk_untyped(0x2000, 4096), CapRights::ALL).unwrap();
        assert_eq!(
            t.copy(0, 1, CapRights::READ),
            Err(CapError::SlotOccupied)
        );
    }

    #[test]
    fn retype_em_slot_dst_ocupado_falha() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0, 0x4000), CapRights::ALL).unwrap();
        t.insert_root(1, mk_untyped(0x10_0000, 0x1000), CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, 0, 0x1000),
            Err(CapError::SlotOccupied)
        );
    }

    #[test]
    fn retype_em_filho_usa_base_do_filho() {
        // Filho tem seu proprio espaco; neto fica em [filho.base + offset, ...).
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x0000, 0x8000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x2000, 0x2000).unwrap(); // filho em [0x2000,0x4000)
        t.retype_untyped(1, 2, 0, 0x1000).unwrap();      // neto em [0x2000,0x3000)
        match t.lookup(2).unwrap().0 {
            CapObject::Untyped { base, .. } => assert_eq!(base, 0x2000),
            _ => unreachable!("teste so cria Untyped"),
        }
    }
}
