# README demo. Render with vhs (https://github.com/charmbracelet/vhs):
#
#   cargo build --release && PATH="$PWD/target/release:$PATH" vhs demo/demo.tape
#
# Writes demo/demo.gif. Uses a throwaway XDG_CONFIG_HOME and working directory, so your real
# configuration is not touched. Your real ~/.ssh is only named, never read: cant refuses first.

Output demo/demo.gif
Require cant
Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 640
Set TypingSpeed 35ms
Set Theme "Builtin Dark"

Hide
Type `export REPO="$PWD" XDG_CONFIG_HOME="$(mktemp -d)" && cd "$(mktemp -d)" && printf 'meeting notes\n' > notes.txt && PS1='$ ' && clear`
Enter
Show

Type "cant run cat ~/.ssh/id_rsa"
Sleep 400ms
Enter
Sleep 2s

Type "cant run cat notes.txt"
Sleep 400ms
Enter
Sleep 2s

Type "cant run curl https://example.com"
Sleep 400ms
Enter
Sleep 2.5s

Type "cant run vim notes.txt"
Sleep 400ms
Enter
Sleep 1.5s
Type "Goadded inside the sandbox"
Escape
Sleep 500ms
Type ":w ~/escape.txt"
Sleep 400ms
Enter
Sleep 2s
Type ":wq"
Enter
Sleep 1s

Type "cat notes.txt"
Enter
Sleep 2s

Type "cant run --explain cat notes.txt | head -12"
Enter
Sleep 4s
