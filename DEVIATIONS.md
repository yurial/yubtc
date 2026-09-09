# DEVIATIONS — журнал пересмотров согласованных решений

Каждая запись фиксирует отклонение/пересмотр ранее согласованного
поведения спецификации. Формат записи: **Change / Was / Now /
Code impact / Tests / Review focus**. Номера `D-XXX` сквозные и
постоянные; записи не удаляются и не переписываются задним числом —
новый пересмотр создаёт новую запись и ссылается на предыдущие.

---

_Журнал пуст: конформная запись D-001 (пересмотр приёма seed, C8)
удалена решением владельца от 2026-08-28 после слияния кода
(yubtc `7db4790`, yubtc-python `cd39857`) — смерженное поведение
описано в specs/spec.md («Seed policy», R-1…R-7). Это осознанное
исключение из правила «записи не удаляются» выше._

## D-002 — Wire-кодирование длин транзакции: LEB128 `to_varint` → Bitcoin CompactSize

- **Change:** все счётчики и длины при сериализации транзакции
  (`TxIn::serialize`, `TxOut::serialize`,
  `Transaction::serialize_stripped`, `Transaction::serialize_wire`)
  кодируются Bitcoin CompactSize (`0xfd`/`0xfe`/`0xff`-префиксы);
  LEB128-хелпер `to_varint` сохранён (тесты и паритет
  `yubtc-python::toVarInt`), но проводкой больше не используется.
- **Was:** длины скриптов и vin/vout-счётчики кодировались
  LEB128-`to_varint` (зеркально `yubtc-python::transaction.toVarInt`)
  — как в v0.1, так и в Phase 13/14.
- **Now:** CompactSize. Два кодирования совпадают байт-в-байт для
  значений 0..=127; выше — расходятся, причём LEB128-байты узел
  парсит как CompactSize-префикс и рассинхронизируется
  («non-minimal varint»), т.е. любая транзакция со скриптом ≥ 128
  байт была консенсус-невалидной.
- **Code impact:** Phase 15 делает такой скрипт достижимым: итоговый
  `scriptSig` P2SH-multisig-входа = `1 + M·(1+|sig|) + pushlen(redeem)`
  — от ~326 байт (2-of-3) до ~665 (15-of-15). `core/src/psbt.rs`
  парсил CompactSize с Phase 14 (расхождение уже было бы поймано
  round-trip-тестом), поэтому правка ограничена четырьмя вызовами
  энкодера в `transaction.rs` + regressive-тесты (`tx_in_uses_compact_
  size_for_large_script_lengths`,
  `multisig_sized_tx_round_trips_through_bitcoin_parse` — round-trip
  через независимый консенсус-десериализатор крейта `bitcoin`).
- **Tests:** все существующие KAT (`vectors.json`,
  `psbt_vectors.json`) не пересчитывались — все задействованные там
  длины < 128, байтовый вывод не изменился; 100%-гейт
  строк/ветвей сохранён.
- **Review focus:** yubtc-python обязан переключить `toVarInt` →
  `compact_size` в тех же позициях `transaction.py` до любого
  xcompat/KAT-прогона Phase 15 (зафиксировано в TODO.md, этап 3);
  расхождение Rust/Python для значений ≥ 128 без этой правки
  недопустимо.

---
