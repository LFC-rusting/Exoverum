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
//! Evolucao futura: quando houver multiplos CSpaces (multi-processo), esta
//! tabela vira um `CNode` e a CDT passa a usar identificadores globais de no.
//! A API publica (`insert_root`/`copy`/`delete`/`revoke`/`retype_untyped`/
//! `lookup`) permanece identica; so a representacao interna muda.

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

/// Referencia a um objeto do kernel. Em v1 so existe `Untyped`; as proximas
/// fases adicionam `Thread` (Thread Control Block), `Frame`, `Event`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapObject {
    /// Regiao de memoria fisica nao-tipada `[base, base + size)`.
    ///
    /// `free_index` e o watermark de alocacao: cada `retype_untyped` cria um
    /// filho em `[base + free_index, base + free_index + n)` e avanca
    /// `free_index += n`. Isso garante que dois filhos **nunca** se sobreponham
    /// (invariante fundamental de capabilities: sem aliasing nao-rastreavel).
    /// `revoke` do proprio Untyped reseta `free_index = 0` (todos os filhos
    /// ja foram destruidos e a regiao pode ser reusada).
    Untyped { base: u64, size: u64, free_index: u64 },
    /// Thread Control Block. `handle` e o indice na tabela `crate::thread`.
    /// O cap so concede direito de operar sobre essa thread (ex: yield_to);
    /// o objeto vive em `thread::THREADS` e nao na CapTable. Mecanismo:
    /// `retype_untyped_to_thread` (Fase 7) sera quem cria pares cap+slot.
    Thread { handle: u8 },
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

    /// Cria em `dst` um novo Untyped filho de `src`, consumindo `new_size`
    /// bytes a partir do watermark `free_index` de `src`. Falha se `src` nao
    /// e Untyped, se `new_size == 0`, ou se extrapolar o que resta.
    ///
    /// O kernel escolhe a base: **impossivel** obter dois filhos sobrepostos.
    #[allow(unreachable_patterns)] // ramo WrongType ativa com novos CapObject
    pub fn retype_untyped(
        &mut self,
        src: CapSlot,
        dst: CapSlot,
        new_size: u64,
    ) -> Result<(), CapError> {
        self.check_range(src)?;
        self.check_range(dst)?;
        if src == dst {
            return Err(CapError::SlotOccupied);
        }
        if !matches!(self.entries[dst as usize], CapEntry::Empty) {
            return Err(CapError::SlotOccupied);
        }
        if new_size == 0 {
            return Err(CapError::InvalidRetype);
        }
        let (base, size, free_index, rights) = match self.entries[src as usize] {
            CapEntry::Cap {
                object: CapObject::Untyped { base, size, free_index },
                rights,
                ..
            } => (base, size, free_index, rights),
            CapEntry::Cap { .. } => return Err(CapError::WrongType),
            CapEntry::Empty => return Err(CapError::SlotEmpty),
        };
        let remaining = size - free_index;
        if new_size > remaining {
            return Err(CapError::InvalidRetype);
        }
        let new_base = base + free_index;
        let new_free = free_index + new_size;
        // Avanca watermark de `src` ANTES de linkar (atomico em rel. a falhas).
        if let CapEntry::Cap { object: CapObject::Untyped { free_index, .. }, .. } =
            &mut self.entries[src as usize]
        {
            *free_index = new_free;
        }
        let child_object = CapObject::Untyped { base: new_base, size: new_size, free_index: 0 };
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
    ///
    /// Adicionalmente: se `slot` e um `Untyped`, `free_index` e resetado
    /// (toda a regiao ficou disponivel para novos retypes).
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
        // Reseta watermark se Untyped (todos filhos ja sumiram).
        if let CapEntry::Cap {
            object: CapObject::Untyped { free_index, .. }, ..
        } = &mut self.entries[slot as usize]
        {
            *free_index = 0;
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
        CapObject::Untyped { base, size, free_index: 0 }
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
    fn retype_aloca_a_partir_do_watermark() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x1000).unwrap();
        match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, size, free_index } => {
                assert_eq!(base, 0x1000, "primeiro filho comeca em parent.base");
                assert_eq!(size, 0x1000);
                assert_eq!(free_index, 0, "filho novo comeca com free_index zero");
            }
            _ => unreachable!("teste so cria Untyped"),
        }
        // Watermark de `src` avancou para 0x1000.
        match t.lookup(0).unwrap().0 {
            CapObject::Untyped { free_index, .. } => assert_eq!(free_index, 0x1000),
            _ => unreachable!("teste so cria Untyped"),
        }
    }

    #[test]
    fn retype_irmaos_nao_aliasam() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x1000).unwrap(); // [0x1000, 0x2000)
        t.retype_untyped(0, 2, 0x1000).unwrap(); // [0x2000, 0x3000)
        let b1 = match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, .. } => base,
            _ => unreachable!("teste so cria Untyped"),
        };
        let b2 = match t.lookup(2).unwrap().0 {
            CapObject::Untyped { base, .. } => base,
            _ => unreachable!("teste so cria Untyped"),
        };
        assert_ne!(b1, b2, "irmaos nunca compartilham base");
        assert_eq!(b2, b1 + 0x1000, "segundo filho vem logo apos o primeiro");
    }

    #[test]
    fn retype_estoura_remaining() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x2000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x1800).unwrap();
        assert_eq!(
            t.retype_untyped(0, 2, 0x1000),
            Err(CapError::InvalidRetype),
            "restante insuficiente"
        );
    }

    #[test]
    fn retype_zero_size_rejeitado() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        assert_eq!(
            t.retype_untyped(0, 1, 0),
            Err(CapError::InvalidRetype)
        );
    }

    #[test]
    fn revoke_reseta_free_index() {
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x1000, 0x4000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x2000).unwrap();
        t.retype_untyped(0, 2, 0x1000).unwrap();
        t.revoke(0).unwrap();
        // Apos revoke, watermark zerou; novo retype retorna ao inicio.
        t.retype_untyped(0, 1, 0x1000).unwrap();
        match t.lookup(1).unwrap().0 {
            CapObject::Untyped { base, .. } => assert_eq!(base, 0x1000),
            _ => unreachable!("teste so cria Untyped"),
        }
    }

    #[test]
    fn retype_em_nao_untyped_seria_wrong_type() {
        // Teste-esqueleto: hoje so temos Untyped, entao nao conseguimos
        // materializar WrongType sem outro tipo. Preservado como
        // placeholder para quando introduzirmos Thread/Frame/Event.
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

    #[test]
    fn retype_filho_tem_free_index_independente() {
        // Filho tem seu proprio watermark (comeca em 0), nao herda do pai.
        let mut t = CapTable::new();
        t.insert_root(0, mk_untyped(0x0000, 0x8000), CapRights::ALL).unwrap();
        t.retype_untyped(0, 1, 0x2000).unwrap(); // parent watermark -> 0x2000
        t.retype_untyped(1, 2, 0x1000).unwrap(); // retype DE dentro do filho 1
        match t.lookup(2).unwrap().0 {
            CapObject::Untyped { base, .. } => assert_eq!(base, 0x0000),
            // ^ base do filho 1 era 0, watermark dele era 0, neto comeca em 0.
            _ => unreachable!("teste so cria Untyped"),
        }
    }
}
