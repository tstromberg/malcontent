                window.require(["ace/ace"], function(a) {
                    if (a) {
                        a.config.init(true);
                        a.define = window.define;
                    }
                    var global = (function () {
                        return this;
                    })();
                    if (!global && typeof window != "undefined") global = window; // can happen in strict mode
                    if (!global && typeof self != "undefined") global = self; // can happen in webworker
                    
                    if (!global.ace)
                        global.ace = a;
                    for (var key in a) if (a.hasOwnProperty(key))
                        global.ace[key] = a[key];
                    global.ace["default"] = global.ace;
                    if (typeof module == "object" && typeof exports == "object" && module) {
                        module.exports = global.ace;
                    }
                });
            })();
        