# vhs tape — wire X autoplay LOOP (~30s, tight). GIF only.
#   render:  vhs assets/demo-loop.tape   ->   assets/wire-demo-loop.gif
# Same real two-agent flow as demo.tape, faster pace for X autoplay.
Output assets/wire-demo-loop.gif

Set Shell bash
Set FontSize 19
Set Width 1340
Set Height 600
Set Padding 30
Set PlaybackSpeed 1.0

Env DEMO_PACE "1.0"

Type "./scripts/demo-show.sh"
Sleep 600ms
Enter
Sleep 33s
