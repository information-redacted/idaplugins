# 「redacted」's IDA Plugins

### Time Wasted (`time_wasted.py`)
This is a really crude port of x64dbg's time wasted debugging widget because lol

Generates a config in `$IDAUSR/time_wasted.config.json` and keeps data in the following places:
- Global data in `$IDAUSR/time_wasted.global_data.json`
- Per-IDB data in the `$ plugin time wasted` netnode

Config file is rather self explanatory, however:
```jsonc
{
    "stop_re_count_when_debugging": false, // whether debugging will stop the reversing counter
    "global": true,                        // count and show global time
    "global_debug": true,                  // show global debugging time
    "per_idb": true,                       // count and show per-idb time
    "per_idb_debug": true,                 // show per-idb debugging time
    "per_session": false,                  // count and show per-session time
    "per_session_debug": true              // show per-session debug time
                                           // --- if global or per_idb are disabled, they won't
                                           //     be saved at all. 
                                           //     debug times are always saved if their
                                           //     reversing timers are enabled, regardless
                                           //     of whether they're shown or not.
}
```
