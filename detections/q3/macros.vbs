Rem Attribute VBA_ModuleType=VBADocumentModule
Option VBASupport 1
Sub AutoOpen()
    Dim str_wscript_spawner As String
    Dim obj_wscript As Object
    Dim int_var_33 As Integer
    Dim str_cmd_command As String

    int_var_33 = 33

    str_wscript_spawner = "[wgvmtx2Wlipp" ' Used to extract wscript using the func_deobfus function

    Set obj_wscript = CreateObject(func_deobfus(str_wscript_spawner)) ' Creates object of Wscript.shell, this allows to execute scripts

    str_cmd_command = func_cmd_deobfus("kTMWELNCn") ' Uses the func_deobfus function to return a cmd command that writes the flag in the user public folder

    str_cmd_command = func_exec_command(obj_wscript, str_cmd_command, int_var_33) 
    ' The last function uses the script host obj_wscript to run the command str_cmd_command and then returns gibberish to overwrite the command.

End Sub

Function func_cmd_deobfus(input_str_unused As String) As String

    Dim str_returned As String
    Dim str_unused As String
    Dim str_spawner_cmd As String
    str_spawner_cmd = "gqh2i|i$3g$ts{ivwlipp2i|i$igls$jwc\4:UhyV{5l$B$G>`Ywivw`Tyfpmg`jpek2x|x"

    str_returned = str_spawner_cmd
    str_returned = func_deobfus(str_returned) ' Deobfuscates the string to cmd.exe /c powershell.exe echo fs_X06QduRw1h > C:\Users\Public\flag.txt
    func_cmd_deobfus = str_returned

End Function

Function func_exec_command(input_wscript As Object, input_cmd_command As String, input_33 As Integer) As String

    Dim str_cmd_command As String
    Dim int_var_5 As Integer
    int_var_5 = 5
    str_cmd_command = input_cmd_command
    
    If (input_33 > int_var_5) Then ' Always true (33 > 5)

        int_var_5 = input_33 - input_33 ' 0
    
        input_obj_wscript.Run str_cmd_command, int_var_5, True
        ' This runs : Wscript.Run cmd.exe /c powershell.exe echo fs_X06QduRw1h > C:\Users\Public\flag.txt, 0, True
        ' This uses the script host to run the cmd_command
    
    End If
    
    str_cmd_command = "MliEmqoAzcRQgcIkDb" ' Overwrites command with gibberish
    func_exec_command = str_cmd_command ' Return gibberish

End Function


Function func_deobfus(input_str As String) As String

    Dim long_var_iterator As Long
    Dim str_returned As String ' The returned val
    Dim int_var_offset As Integer
    int_var_offset = 4

    For long_var_iterator = 1 To Len(input_str) ' This loops from 1 to len of input which is from 1 to 13

        str_returned = str_returned & Chr(Asc(Mid(input_str, long_var_iterator, 1)) - int_var_offset)
        ' For the first call in Autorun [wgvmtx2Wlipp the runction returns Wscript.Shell
        ' For the second call in func_cmd_deobfus it returns cmd.exe /c powershell.exe echo fs_X06QduRw1h > C:\Users\Public\flag.txt
    Next long_var_iterator
    
    func_deobfus = str_returned

End Function