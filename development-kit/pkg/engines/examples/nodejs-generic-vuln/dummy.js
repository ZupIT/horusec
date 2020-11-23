/**
 * Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file contains dummy information data

var dummy_info = {
  // Customer module configs
  "users": [
    {
      "username": "admin",
      "password": "admin"
    },
    {
      "username": "roberto",
      "password": "asdfpiuw981"
    }
  ],

  "products": [
    {
      "name": "My public privacy",
      "description": "Grant privacy in public to watch your favorite programs",
      "price": parseInt(Math.random() * 100),
      "image": "product_1.jpg"
    },
    {
      "name": "The USB rocket",
      "description": "Be happy with your USB rocket. Functionality: none. Usability: none. The best choice!",
      "price": parseInt(Math.random() * 100),
      "image": "product_2.jpg"
    },
    {
      "name": "Walker watermelons",
      "description": "Take a walk your watermelons and make it feel comfortable.",
      "price": parseInt(Math.random() * 100),
      "image": "product_3.jpg"
    },
    {
      "name": "Potty Putter",
      "description": "The game for the avid golfers!",
      "price": 20,
      "image": "product_4.jpg"
    },
    {
      "name": "Phone Fingers",
      "description": "Phone fingers work perfectly well with iPhone's touch screen and prevent fingerprints and smudges",
      "price": 3,
      "image": "product_5.jpg"
    },
    {
      "name": "Daddle",
      "description": "Be the best father with Daddle: dad's saddle for horsing around.",
      "price": parseInt(Math.random() * 100),
      "image": "product_6.jpg"
    },
    {
      "name": "HD Vision",
      "description": "Reality is not enough for you? Improve your live with the HD vision glasses.",
      "price": parseInt(Math.random() * 100),
      "image": "product_7.jpg"
    },
    {
      "name": "Hangs free",
      "description": "Say goodbye to the cumbersome cables with the authentic hands free.",
      "price": parseInt(Math.random() * 100),
      "image": "product_8.jpg"
    }
  ]
}

module.exports = dummy_info;