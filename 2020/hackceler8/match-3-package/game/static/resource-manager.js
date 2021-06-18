// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
"use strict"

const resourceManager = {}

resourceManager.ResourceManager = class ResourceManager {
  r

  constructor() {
    this.r = {}
  }

  loadResources(listOfResources) {
    return new Promise((resolve, reject) => {
      this.loadWorker(listOfResources, resolve, reject)
    })
  }

  restartProgressTimer(resolve, reject) {
    setTimeout(() => {
      this.updateProgress(resolve, reject)
    }, 100)
  }

  updateProgress(resolve, reject) {
    let total = 0
    let ready = 0
    Object.keys(this.r).forEach(key => {
      const entry = this.r[key]

      switch (entry.type) {
        case "image":
          if (entry.img.complete) {
            ready++
          }
          break

        case "audio":
          if (entry.audio.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA) {
            ready++
          }
          break

        default:
          ready++
      }

      total++
    })

    this.setProgressBar(ready, total)

    if (total === ready) {
      resolve()
      this.hideProgressBar()
    } else {
      this.restartProgressTimer(resolve, reject)
    }
  }

  hideProgressBar() {
    const e = document.getElementById("progress-box")
    e.addEventListener("transitionend", () => {
      e.style.display = "none"
      e.innerText = ""
    }, { once: true })
    e.style.opacity = "0"
  }

  setProgressBar(current, total) {
    const e = document.getElementById("progress-box")
    e.innerText = `${current} / ${total}`

    if (total === 0) {
      current = 1
      total = 1
    }
    const p = (100 * current / total)|0
    e.style.background =
        `linear-gradient(90deg, rgb(0, 51, 121) ${p}%, rgba(75, 75, 75) ${p}%)`

    e.style.opacity = "100"
    e.style.display = "block"
  }

  loadAudio(entry) {
    entry.audio = new Audio(entry.path);
  }

  loadImage(entry) {
    let img = new Image()
    img.src = entry.path
    entry.img = img
  }

  loadWorker(listOfResources, resolve, reject) {
    // Start loading.
    listOfResources.forEach(entry => {
      this.r[entry.name] = entry  // Entry also contains meta-data.

      switch (entry.type) {
        case "image":
          this.loadImage(entry)
          break

        case "audio":
          this.loadAudio(entry)
          break
      }
    })

    this.restartProgressTimer(resolve, reject)
  }
}
