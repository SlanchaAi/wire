# vhs tape — wire launch HERO demo (~60s, readable). MP4 (X-native + landing hero) + GIF (README).
#   render:  vhs assets/demo.tape   ->   assets/wire-demo.mp4 + assets/wire-demo.gif
# Drives scripts/demo-show.sh (the real two-agent bilateral flow, paced for reading).
Output assets/wire-demo.mp4
Output assets/wire-demo.gif

Set Shell bash
Set FontSize 19
Set Width 1340
Set Height 600
Set Padding 30
Set PlaybackSpeed 1.0

Env DEMO_PACE "2.2"

Type "./scripts/demo-show.sh"
Sleep 600ms
Enter
Sleep 62s
