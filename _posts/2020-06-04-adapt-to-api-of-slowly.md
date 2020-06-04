---
layout:     post
title:      "Adapt to New API of Slowly"
date:       2020-06-04 
author:     "withparadox2"
catalog: true
tags:
  - javascript
---

## Background

I wrote a web version of [Slowly](https://github.com/withparadox2/ShowSlowly) using Vue.js last year, which provided some useful functions unsupported, even now, by the official app. It runs well till yesterday when I failed to sign in. At first, I suspected the server might have detected what I had done was illegal and blocked me from further use, since my app can extract accurate locations of friends, show content of a letter even before it has arrived, and send photos without acceptances from receiver, which, to some extent, may violate their licences.  

After some investigations, it turned out, luckily, that they just upgraded the sercurity level of server to protect information of users. I spent several hours studing their strategies and modifying my code and eventually made the app sail out again. 

This post elaborates on the problems I encountered during the process and how I finally solve them.

## Charles didn't help

I created the first version with help of Charles to intercept requests sending from the Slowly app running in my phone with Android 7 installed. In this way, I was able to see the content sealed with https and recorded all important APIs and hence built my own version. In order to figure out what went wrong I had to check first the requests sending by the latest version of Slowly. However, installation of certificates is forbidden in Android with platform version above 7, so I turned to VirtualXposed, which promises a way to hack https in Android phones running on an OS of any version without root. It didn't work either. 

Before digging into VirtualXposed I tried doing it on Windows instead. Though there were many problmes, like mismatch of architectures, missing of services from google play required by Slowly and my inability to separate a runnable apk from a bundle, I solved them patiently and finally intercepted requests in Charles. 

It turned out that besides using a new API, the login request also brought an encrypted parameter of `otp`, changing each time, which obviously was generated in client. My next task was to find out how to generate `otp`.
```
otp:qxg6AGYQ4y5rDVaSaiRYjZ3WNwbalO
```

P.S. Charles did help. A lot!

## Generate otp

There was little I could do withought reading the code. So I downloaded the latest apk, unpacked it, and found the source file `index.android.bundle` directly under the folder `assets`, which turned out to be a large compressed javascript file with the size of nearly 3.5 Mb. I copied it to another file named `index.js`, opening it with VS Code. The messy code soon filled the screen and made my computer roar at it's best. 

![Code Overview](/img/post/2020-06-04-adapt-to-api-of-slowly/bundle_code_overview.png)

I extracts a piece of code related to the new api `/users/me/v2`, and it's easy to find `otp` is passed from the caller side.

```javascript
__d(function(g, r, i, a, m, e, d) {
  ......
  e.getMe = function(n) {
    var P = n.otp,
      y = void 0 === P ? null : P,
      S = {
        ......
        otp: y
      };
    return fetch(t.API_URL + '/users/me/v2?token=' + o, {
      method: 'POST',
      headers: t.headers,
      body: JSON.stringify(S)
    }).then(t.handleApiErrors).then(function(n) {
      return n.json()
    }).then(function(n) {
      return n
    }).catch(function(n) {
      throw n
    })
  };
}, 962, [1, 924, 598]);
```
Code blocks referencing `getMe` are all surrounded with a large piece of messed code, which makes it difficult to figure out. Instead, I searched `otp` and found the core logic to generate `otp`: 

```javascript
__d(function(g, r, i, a, m, e, d) {
  ......
  var t = r(d[0]);
  var o = t(r(d[2]))
  e.genOTP = function(t) {
    var n = t.timestamp,
        c = t.uid;
    return new o.default(
      '+DP;=SW`DGX&n|]OGoGkj/4XqPw?^Fclc2F-_V~D=rquG+L(kW_xzVR=slp+Yj;B', 
      30
    ).encode(parseInt(n), parseInt(c), Math.floor(1e5 + 9e5 * Math.random()))
  };
  ......
}, 923, [1, 924, 925]);
```

`genOTP` accepts an object containing two keys, one is `timestam`, another one is `uid`.

Before going more, the structure of a module needs to be explainded a little. Each module is defined in a factory function passed along with another two parameters——an integer and an array——as arguments to a function `_d`. The second parameter, i.e. the integer, indicates the index of the module, and the third parameter is an array of index of module it depends on.

```javascript
__d(function(g,r,i,a,m,e,d){
  ......
},923,[1,924,925]);
```
Each factory function accepts 7 parameters, the most important three ones are:

- r: require, `r(12)` means to import a module with index 12
- e: exports, `e.getMe = function` means to export a function `getMe` from this module
- d: array of dependencies, `r(d[1])` means to import a module whose index is `d[1]`

In this case, `d` is `[1, 924, 925]`, then `t = r(d[0])` equals `t = r(1)` and `o = t(r(d[2]))` equals `o = r(1)(r(925))`, hence the code above can be transformed to something below:

```javascript
var otp = new (__r(1)(__r(925)).default)(
    '+DP;=SW`DGX&n|]OGoGkj/4XqPw?^Fclc2F-_V~D=rquG+L(kW_xzVR=slp+Yj;B',
    30
  ).encode(
    parseInt(Date.now()),
    parseInt(0),
    Math.floor(1e5 + 9e5 * Math.random())
)
console.log(otp)
```
Put this piece of code at the bottom of `index.js` and run `node index.js`. Supress some(a lot of) errors related to ReactNative and we will get an output, pretty much like the one capured in a request:

```
j4P89Am5g96GPkKwuYiZ5xE3wgbLYO
```

Now, let's look at the detail of module 1: 

```javascript
__d(function(g, r, i, a, m, e, d) {
  m.exports = function(n) {
    return n && n.__esModule ? n : {
      default: n
    }
  }
}, 1, []);
```
Since module 1 does nothing except returning the input function back, the invocation of module 1 can be eliminated. Next, we will see what module 925 looks like:

```javascript
__d(function(g, r, i, a, m, e, d) {
  !(function(t, s) {
    if ("function" == typeof define && define.amd) define(["exports"], s);
    else if (void 0 !== e) s(e);
    else {
      var h = {};
      s(h), t.Hashids = h
    }
  })(this, function(t) {
    ......
    var h = (function() {
      ......
    })();
    t.default = h
  })
}, 925, [])
```
Module 925 is an immediate function which at last export function `h` as `default` property of `e`, and it can be simplified to:

```javascript
__d(function(g, r, i, a, m, e, d) {
  var h = (function() {
    // a large piece code
    ......
  })();
  e.default = h
}, 925, [])
```
What is still unkown to us is how to get `timestamp` and `uid` for `genOTP`. After investigating the code again I sifted the most important logic related to process of sending request of `getMe`:

```javascript
__d(function(g, r, i, a, m, e, d) {
  ......
  var p = r(d[7]),
    E = r(d[10]),
    ......
  function X() {
      var t, n, s, o, x, _, S, y, h, R, T, b, O, w;
      return c.default.wrap(function(c) {
        for (;;) switch (c.prev = c.next) {
          ......
          case 11:
            return S = c.sent, c.prev = 12, c.next = 15, (0, u.call)(p.getTime);
          case 15:
            return y = c.sent, c.next = 18, (0, u.select)(E.getMyID);
          case 18:
            return h = c.sent, c.next = 21, (0, u.call)(p.genOTP, {
              timestamp: parseInt(y.now),
              uid: parseInt(h)
            });
          case 21:
            return R = c.sent, c.next = 24, (0, u.call)(l.getMe, {
              token: n,
              location_code: s,
              location: o,
              device: S.device,
              otp: R
            });
            ......
        }
      }, C, null, [
        [12, 45]
      ])
    }
}, 969, [383, 1, 46, 136, 623, 948, 962, 923, 968, 952, 963, 633, 2, 634, 636, 738, 920, 353])
```
This code block shows that we can get `uid` through `E.getMyID`, where `E` is imported from module 923 and get `timestamp` by calling `p.getTime`, where `p` implies module 963, same one as `genOTP`. 

It's time to uncover the real face of `getTime` and `getMyID`:

```javascript
__d(function(g, r, i, a, m, e, d) {
  ......
  e.getTime = function() {
    return fetch(n.API_URL + '/timestamp', {
      timeout: 2e3
    }).then(n.handleApiErrors).then(function(t) {
      return t.json()
    }).then(function(t) {
      return t
    }).catch(function(t) {
      throw t
    })
  }
}, 962, [1, 924, 598]);

__d(function(g, r, i, a, m, e, d) {
  ......
  var _ = function(t) {
    return t.me.id ? t.me.id : 0
  };
  e.getMyID = _;
}, 963, [1, 18, 46, 964, 356, 919, 965]);
```
Since we don't have any information before signing in, thus `uid` can always be set as `0`.

Combining all the code metioned above together, we get to a final, feasible piece of code:
```javascript
const Encryption = (function() {
  ......
})()

export default function getOtp() {
  getTimestamp().then((time) => {
    return new Encryption(
      "+DP;=SW`DGX&n|]OGoGkj/4XqPw?^Fclc2F-_V~D=rquG+L(kW_xzVR=slp+Yj;B",
      30
    ).encode(
      parseInt(time),
      parseInt(0),
      Math.floor(1e5 + 9e5 * Math.random())
    );
  })
}
```