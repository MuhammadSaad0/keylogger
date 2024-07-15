#### A self-exercise to work with Windows low-level processes. The keylogger captures keystrokes on a Windows machine and logs them into a SQLite DB. Additionally, logged data can be fetched from a mongoose server endpoint.
#### Running with gcc: `gcc keylogger.c sqlite3.c mongoose.c -lwsock32`
