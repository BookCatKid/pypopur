"""ThingClips/Tuya OEM SDK internals, ported opcode-faithful from the Popur
S7 2.0.0 APK (apktool smali is canonical).

Layer map (Java → Python):

- ``DevUtil`` validation/RAW conversion → :mod:`pypopur.sdk.validation`
- ``SchemaBean`` + ``SchemaMapper`` → :mod:`pypopur.sdk.schema`
- ``HexUtil``/``ByteUtils`` → :mod:`pypopur.sdk.hexutil`
- ``AESUtil``/``AesGcmUtil``/``MD5``/``CRC32Utils`` → :mod:`pypopur.sdk.crypto`
- ``SandO``/``SandRMap`` → :mod:`pypopur.sdk.sando`
- ``qdddqdp`` (ThingMessageCache dedup) → :mod:`pypopur.sdk.dedup`
- ``TimeStampManager`` → :mod:`pypopur.sdk.timestamp`
- ``pbbppqb`` sign/CRC helpers → :mod:`pypopur.sdk.mqtt_sign`
- ``qpqddqd`` + per-pv framing/decoder classes → :mod:`pypopur.sdk.mqtt_framing`
- ``bqbppdq``/``qpqbppd``/``pqdppqd`` session + ``PhoneUtil`` →
  :mod:`pypopur.sdk.mqtt_session`, :mod:`pypopur.sdk.device_id`
- ``ddbdpqb``/``bbbdppp`` LAN request assembly → :mod:`pypopur.sdk.lan_framing`
- ``DeviceRespBean``/``DeviceBean``/``ppqqqpb``/``ddpdbbp``/``pdppddb``
  device caches + central DP ingest → :mod:`pypopur.sdk.device_cache`
- ``qqdbbpp``/``bpqqdpq``/``dqdpbbd``/``dddpppb``/``bddqdbd``/``qpbpqpq``
  LAN control chain + ``FrameTypeEnum``/``ActiveEnum``/``HgwBean``/
  ``ThingLocalControlBean`` → :mod:`pypopur.sdk.lan_control`
- ``AbsThingDevice`` publishDps entries + ``qqqbbbd`` handler chain +
  ``qpbpqpq`` DevModel + ``CommunicationEnum``/
  ``ThingDevicePublishModeEnum`` → :mod:`pypopur.sdk.comm_pipeline`
- ``ThingApiSignManager``/``ThingNetworkSecurity`` signing + native
  primitive wrappers → :mod:`pypopur.sdk.security`
- ``ThingApiParams``/``ApiParams`` + ``Business$RequestTask``/``Business``
  + ``OKHttpBusinessRequest`` + ``dbppbbp`` device APIs +
  ``ThingSmartNetWork`` statics → :mod:`pypopur.sdk.atop`
- ``GwBroadcastMonitorService`` UDP discovery + ``GwBroadcastMonitorModel``
  dispatch + ``qbdpdpp`` (ThingSmartHardwareManager) + ``HgwBean``/
  ``ActiveEnum`` → :mod:`pypopur.sdk.discovery`
- ``bdqqqbp`` (LowPowerDeviceManager) wake task + ``m/w/`` publish +
  checkAwakeStatus → :mod:`pypopur.sdk.low_power`
- ``ThingNetworkApi``/``ThingNetworkInterface`` JNI surface +
  ``DevTransferService`` (live/connecting gw maps, heartbeat watchdog) +
  ``GwTransferModel`` (executor hops, multi-package reassembly, handler
  dispatch) + ``bdbbqqd`` proxy + ``dbpbdpb`` hgw cache + ``dpppdpq``
  (ThingHardwareManager: control, ``onDevResponse`` dispatch, lpv response
  parsers ``bqqbpqb``/``bqpbddq``/``bdbbqbd`` family) →
  :mod:`pypopur.sdk.lan_session`
- THING_MODEL subsystem — ``qqbbddb`` LinkFilterConvertUtil,
  ``bdpqppd``/``bppdpdq``/``qqqpdpb`` property/action/event converters,
  ``bbdppqp`` type-spec validation, ``qpppdbb`` model cache,
  ``ThingSmartThing*`` beans, ``qdbpqqq`` link control,
  ``dbddpbp``/``dqqpqbq`` link handlers and the
  ``sendLinkMessageByMqtt/Http`` transports →
  :mod:`pypopur.sdk.thing_model`
"""
