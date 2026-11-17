#!/bin/bash
# Runs inside the emulator started by reactivecircus/android-emulator-runner.
# Always dumps the DroidFS logcat lines, then exits with Gradle's exit code.
set +e
./gradlew connectedDebugAndroidTest -Pabi=x86_64 -Pnouniversal -PdisableCryFS=true -PdisableGocryptfs=true --stacktrace
code=$?
adb logcat -d -s DroidFS:I > emulator-logcat.txt 2>&1
cat emulator-logcat.txt
exit $code
