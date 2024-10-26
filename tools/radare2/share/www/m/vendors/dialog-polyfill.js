!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e=e||self).dialogPolyfill=t()}(this,function(){"use strict";var i=window.CustomEvent;function n(e,t){var o="on"+t.type.toLowerCase();return"function"==typeof e[o]&&e[o](t),e.dispatchEvent(t)}function a(e){for(;e;){if("dialog"===e.localName)return e;e=e.parentElement||(e.parentNode?e.parentNode.host:null)}return null}function o(e){for(;e&&e.shadowRoot&&e.shadowRoot.activeElement;)e=e.shadowRoot.activeElement;e&&e.blur&&e!==document.body&&e.blur()}function r(e){return e&&e.hasAttribute("method")&&"dialog"===e.getAttribute("method").toLowerCase()}function e(e){return e.isConnected||document.body.contains(e)}function l(e){if(e.submitter)return e.submitter;var t=e.target;if(!(t instanceof HTMLFormElement))return null;var o=p.formSubmitter;return(o=o?o:("getRootNode"in(e=e.target)&&e.getRootNode()||document).activeElement)&&o.form===t?o:null}function s(e){var t,o,i,n;e.defaultPrevented||(t=e.target,o=p.imagemapUseValue,i=l(e),null===o&&i&&(o=i.value),(n=a(t))&&"dialog"===(i&&i.getAttribute("formmethod")||t.getAttribute("method"))&&(e.preventDefault(),null!=o?n.close(o):n.close()))}function t(t){var o,i,n,a;this.dialog_=t,this.replacedStyleTop_=!1,this.openAsModal_=!1,t.hasAttribute("role")||t.setAttribute("role","dialog"),t.show=this.show.bind(this),t.showModal=this.showModal.bind(this),t.close=this.close.bind(this),t.addEventListener("submit",s,!1),"returnValue"in t||(t.returnValue=""),"MutationObserver"in window?new MutationObserver(this.maybeHideModal.bind(this)).observe(t,{attributes:!0,attributeFilter:["open"]}):(o=!1,i=function(){o?this.downgradeModal():this.maybeHideModal(),o=!1}.bind(this),a=function(e){e.target===t&&(o|=e.type.substr(0,(e="DOMNodeRemoved").length)===e,window.clearTimeout(n),n=window.setTimeout(i,0))},["DOMAttrModified","DOMNodeRemoved","DOMNodeRemovedFromDocument"].forEach(function(e){t.addEventListener(e,a)})),Object.defineProperty(t,"open",{set:this.setOpen.bind(this),get:t.hasAttribute.bind(t,"open")}),this.backdrop_=document.createElement("div"),this.backdrop_.className="backdrop",this.backdrop_.addEventListener("mouseup",this.backdropMouseEvent_.bind(this)),this.backdrop_.addEventListener("mousedown",this.backdropMouseEvent_.bind(this)),this.backdrop_.addEventListener("click",this.backdropMouseEvent_.bind(this))}i&&"object"!=typeof i||((i=function(e,t){t=t||{};var o=document.createEvent("CustomEvent");return o.initCustomEvent(e,!!t.bubbles,!!t.cancelable,t.detail||null),o}).prototype=window.Event.prototype),t.prototype={get dialog(){return this.dialog_},maybeHideModal:function(){this.dialog_.hasAttribute("open")&&e(this.dialog_)||this.downgradeModal()},downgradeModal:function(){this.openAsModal_&&(this.openAsModal_=!1,this.dialog_.style.zIndex="",this.replacedStyleTop_&&(this.dialog_.style.top="",this.replacedStyleTop_=!1),this.backdrop_.parentNode&&this.backdrop_.parentNode.removeChild(this.backdrop_),p.dm.removeDialog(this))},setOpen:function(e){e?this.dialog_.hasAttribute("open")||this.dialog_.setAttribute("open",""):(this.dialog_.removeAttribute("open"),this.maybeHideModal())},backdropMouseEvent_:function(e){this.dialog_.hasAttribute("tabindex")?this.dialog_.focus():(t=document.createElement("div"),this.dialog_.insertBefore(t,this.dialog_.firstChild),t.tabIndex=-1,t.focus(),this.dialog_.removeChild(t));var t=document.createEvent("MouseEvents");t.initMouseEvent(e.type,e.bubbles,e.cancelable,window,e.detail,e.screenX,e.screenY,e.clientX,e.clientY,e.ctrlKey,e.altKey,e.shiftKey,e.metaKey,e.button,e.relatedTarget),this.dialog_.dispatchEvent(t),e.stopPropagation()},focus_:function(){var e=(e=!(e=this.dialog_.querySelector("[autofocus]:not([disabled])"))&&0<=this.dialog_.tabIndex?this.dialog_:e)||function e(t){var o=["button","input","keygen","select","textarea"].map(function(e){return e+":not([disabled])"}),i=(o.push('[tabindex]:not([disabled]):not([tabindex=""])'),t.querySelector(o.join(", ")));if(!i&&"attachShadow"in Element.prototype)for(var n=t.querySelectorAll("*"),a=0;a<n.length&&!(n[a].tagName&&n[a].shadowRoot&&(i=e(n[a].shadowRoot)));a++);return i}(this.dialog_);o(document.activeElement),e&&e.focus()},updateZIndex:function(e,t){if(e<t)throw new Error("dialogZ should never be < backdropZ");this.dialog_.style.zIndex=e,this.backdrop_.style.zIndex=t},show:function(){this.dialog_.open||(this.setOpen(!0),this.focus_())},showModal:function(){if(this.dialog_.hasAttribute("open"))throw new Error("Failed to execute 'showModal' on dialog: The element is already open, and therefore cannot be opened modally.");if(!e(this.dialog_))throw new Error("Failed to execute 'showModal' on dialog: The element is not in a Document.");if(!p.dm.pushDialog(this))throw new Error("Failed to execute 'showModal' on dialog: There are too many open modal dialogs.");!function(e){for(;e&&e!==document.body;){var o=window.getComputedStyle(e),t=function(e,t){return!(void 0===o[e]||o[e]===t)};if(o.opacity<1||t("zIndex","auto")||t("transform","none")||t("mixBlendMode","normal")||t("filter","none")||t("perspective","none")||"isolate"===o.isolation||"fixed"===o.position||"touch"===o.webkitOverflowScrolling)return 1;e=e.parentElement}}(this.dialog_.parentElement)||console.warn("A dialog is being shown inside a stacking context. This may cause it to be unusable. For more information, see this link: https://github.com/GoogleChrome/dialog-polyfill/#stacking-context"),this.setOpen(!0),this.openAsModal_=!0,p.needsCentering(this.dialog_)?(p.reposition(this.dialog_),this.replacedStyleTop_=!0):this.replacedStyleTop_=!1,this.dialog_.parentNode.insertBefore(this.backdrop_,this.dialog_.nextSibling),this.focus_()},close:function(e){if(!this.dialog_.hasAttribute("open"))throw new Error("Failed to execute 'close' on dialog: The element does not have an 'open' attribute, and therefore cannot be closed.");this.setOpen(!1),void 0!==e&&(this.dialog_.returnValue=e);e=new i("close",{bubbles:!1,cancelable:!1});n(this.dialog_,e)}};var d,u,c,h,p={reposition:function(e){var t=document.body.scrollTop||document.documentElement.scrollTop,o=t+(window.innerHeight-e.offsetHeight)/2;e.style.top=Math.max(t,o)+"px"}};return p.isInlinePositionSetByStylesheet=function(e){for(var t=0;t<document.styleSheets.length;++t){var o=document.styleSheets[t],i=null;try{i=o.cssRules}catch(e){}if(i)for(var n=0;n<i.length;++n){var a=i[n],r=null;try{r=document.querySelectorAll(a.selectorText)}catch(e){}if(r&&function(e,t){for(var o=0;o<e.length;++o)if(e[o]===t)return 1}(r,e)){r=a.style.getPropertyValue("top"),a=a.style.getPropertyValue("bottom");if(r&&"auto"!==r||a&&"auto"!==a)return!0}}}return!1},p.needsCentering=function(e){return"absolute"===window.getComputedStyle(e).position&&(!("auto"!==e.style.top&&""!==e.style.top||"auto"!==e.style.bottom&&""!==e.style.bottom)&&!p.isInlinePositionSetByStylesheet(e))},p.forceRegisterDialog=function(e){if((window.HTMLDialogElement||e.showModal)&&console.warn("This browser already supports <dialog>, the polyfill may not work correctly",e),"dialog"!==e.localName)throw new Error("Failed to register dialog: The element is not a dialog.");new t(e)},p.registerDialog=function(e){e.showModal||p.forceRegisterDialog(e)},p.DialogManager=function(){this.pendingDialogStack=[];var t=this.checkDOM_.bind(this);this.overlay=document.createElement("div"),this.overlay.className="_dialog_overlay",this.overlay.addEventListener("click",function(e){this.forwardTab_=void 0,e.stopPropagation(),t([])}.bind(this)),this.handleKey_=this.handleKey_.bind(this),this.handleFocus_=this.handleFocus_.bind(this),this.zIndexLow_=1e5,this.zIndexHigh_=100150,this.forwardTab_=void 0,"MutationObserver"in window&&(this.mo_=new MutationObserver(function(e){var i=[];e.forEach(function(e){for(var t,o=0;t=e.removedNodes[o];++o)t instanceof Element&&("dialog"===t.localName&&i.push(t),i=i.concat(t.querySelectorAll("dialog")))}),i.length&&t(i)}))},p.DialogManager.prototype.blockDocument=function(){document.documentElement.addEventListener("focus",this.handleFocus_,!0),document.addEventListener("keydown",this.handleKey_),this.mo_&&this.mo_.observe(document,{childList:!0,subtree:!0})},p.DialogManager.prototype.unblockDocument=function(){document.documentElement.removeEventListener("focus",this.handleFocus_,!0),document.removeEventListener("keydown",this.handleKey_),this.mo_&&this.mo_.disconnect()},p.DialogManager.prototype.updateStacking=function(){for(var e,t=this.zIndexHigh_,o=0;e=this.pendingDialogStack[o];++o)e.updateZIndex(--t,--t),0===o&&(this.overlay.style.zIndex=--t);var i=this.pendingDialogStack[0];i?(i.dialog.parentNode||document.body).appendChild(this.overlay):this.overlay.parentNode&&this.overlay.parentNode.removeChild(this.overlay)},p.DialogManager.prototype.containedByTopDialog_=function(e){for(;e=a(e);){for(var t,o=0;t=this.pendingDialogStack[o];++o)if(t.dialog===e)return 0===o;e=e.parentElement}return!1},p.DialogManager.prototype.handleFocus_=function(e){var t=e.composedPath?e.composedPath()[0]:e.target;if(!this.containedByTopDialog_(t)&&(document.activeElement!==document.documentElement&&(e.preventDefault(),e.stopPropagation(),o(t),void 0!==this.forwardTab_)))return(e=this.pendingDialogStack[0]).dialog.compareDocumentPosition(t)&Node.DOCUMENT_POSITION_PRECEDING&&(this.forwardTab_?e.focus_():t!==document.documentElement&&document.documentElement.focus()),!1},p.DialogManager.prototype.handleKey_=function(e){var t,o;this.forwardTab_=void 0,27===e.keyCode?(e.preventDefault(),e.stopPropagation(),t=new i("cancel",{bubbles:!1,cancelable:!0}),(o=this.pendingDialogStack[0])&&n(o.dialog,t)&&o.dialog.close()):9===e.keyCode&&(this.forwardTab_=!e.shiftKey)},p.DialogManager.prototype.checkDOM_=function(t){this.pendingDialogStack.slice().forEach(function(e){-1!==t.indexOf(e.dialog)?e.downgradeModal():e.maybeHideModal()})},p.DialogManager.prototype.pushDialog=function(e){var t=(this.zIndexHigh_-this.zIndexLow_)/2-1;return!(this.pendingDialogStack.length>=t)&&(1===this.pendingDialogStack.unshift(e)&&this.blockDocument(),this.updateStacking(),!0)},p.DialogManager.prototype.removeDialog=function(e){e=this.pendingDialogStack.indexOf(e);-1!==e&&(this.pendingDialogStack.splice(e,1),0===this.pendingDialogStack.length&&this.unblockDocument(),this.updateStacking())},p.dm=new p.DialogManager,p.formSubmitter=null,p.imagemapUseValue=null,void 0===window.HTMLDialogElement&&((d=document.createElement("form")).setAttribute("method","dialog"),"dialog"!==d.method&&(d=Object.getOwnPropertyDescriptor(HTMLFormElement.prototype,"method"))&&(u=d.get,d.get=function(){return r(this)?"dialog":u.call(this)},c=d.set,d.set=function(e){return"string"==typeof e&&"dialog"===e.toLowerCase()?this.setAttribute("method",e):c.call(this,e)},Object.defineProperty(HTMLFormElement.prototype,"method",d)),document.addEventListener("click",function(e){if(p.formSubmitter=null,p.imagemapUseValue=null,!e.defaultPrevented){var t=e.target;if((t="composedPath"in e?e.composedPath().shift()||t:t)&&r(t.form)){if(!("submit"===t.type&&-1<["button","input"].indexOf(t.localName))){if("input"!==t.localName||"image"!==t.type)return;p.imagemapUseValue=e.offsetX+","+e.offsetY}a(t)&&(p.formSubmitter=t)}}},!1),document.addEventListener("submit",function(e){var t,o=e.target;a(o)||"dialog"===((t=l(e))&&t.getAttribute("formmethod")||o.getAttribute("method"))&&e.preventDefault()}),h=HTMLFormElement.prototype.submit,HTMLFormElement.prototype.submit=function(){if(!r(this))return h.call(this);var e=a(this);e&&e.close()}),p});