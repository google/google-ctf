#include <Arduboy2.h>
#include "bitmaps.h"
#include "menu.h"
#include "game.h"

typedef void (*FunctionPointer) ();

const FunctionPointer PROGMEM gameStates[] = {
  stateIntro,
  stateGameInit,
  stateGamePlaying,
  stateGameOver,
  stateGameWin,
};

void setup()
{
  arduboy.begin();
  arduboy.initRandomSeed();
  arduboy.setFrameRate(30);

  tunes.initChannel(PIN_SPEAKER_1);
  tunes.initChannel(PIN_SPEAKER_2);
}

void loop() {
  if (!(arduboy.nextFrame())) return;
  arduboy.pollButtons();
  arduboy.clear();
  ((FunctionPointer) pgm_read_word (&gameStates[gameState]))();
  arduboy.display();
}
