AJS.$(function() {

    if (AJS.$("#login-form").length) {
        loadCorpLogin(AJS.$("#login-form"));
    } else {
        AJS.$("iframe").ready(function () {
            var iframe = AJS.$("#gadget-0");
            loadCorpLogin(AJS.$("#" + iframe[0].id).contents().find("#loginform"));

        });
    }

    function addReference() {
        var redirectUrl;
        if(location.search.indexOf("os_destination") > -1){
            redirectUrl = AJS.contextPath() + "/plugins/servlet/saml/auth?os_destination=" + AJS.$("input[name='os_destination']").val();
        }else {
            redirectUrl = AJS.contextPath() + "/plugins/servlet/saml/auth?os_destination=/secure/Dashboard.jspa";
        }
        AJS.$("#ssoButton").attr("href", redirectUrl) ;
    }

    function loadCorpLogin(loginForm) {
        if (loginForm.length === 1) {
            var loginFormId = loginForm[0].id;
            loginForm.hide();

            if(loginFormId === "login-form") {
                AJS.$('<div class="field-group"><a class="aui-button aui-style aui-button-primary" id="ssoButton" style="align:center;">Use Corporate Login</a></div><h2 style="margin-top:10px"></h2>').insertBefore(AJS.$("#" + loginFormId + " .form-body"));
            } else {
                AJS.$('<div class="field-group"><a class="aui-button aui-style aui-button-primary" id="ssoButton" style="margin-left:100px;margin-top:5px;">Use Corporate Login</a></div>').insertBefore(AJS.$("#gadget-0"));
            }

            addReference();

            var query = location.search.substr(1);
            query.split("&").forEach(function(part) {
                var item = part.split("=");
                if (item.length === 2 && item[0] === "samlerror") {
                    var errorKeys = {};
                    errorKeys["general"] = "General SAML configuration error";
                    errorKeys["user_not_found"] = "User was not found";
                    errorKeys["plugin_exception"] = "SAML plugin internal error";
                    loginForm.show();
                    var message = '<div class="aui-message closeable error">' + errorKeys[item[1]] + '</div>';
                    AJS.$(message).insertBefore(loginForm);
                }
            });

            if (location.search === '?logout=true') {
                $.ajax({
                    url: AJS.contextPath() + "/plugins/servlet/saml/getajaxconfig?param=logoutUrl",
                    type: "GET",
                    error:function () {
                    },
                    success: function (response) {
                        if (response !== "") {
                            AJS.$('<p>Please wait while we redirect you to your company log out page</p>').insertBefore(loginForm);
                            window.location.href = response;
                            return;
                        }
                    }
                });
                return;
            }

            AJS.$.ajax({
                url: AJS.contextPath() + "/plugins/servlet/saml/getajaxconfig?param=idpRequired",
                type: "GET",
                error:function () {
                },
                success: function (response) {
                    if (response === "true") {

                        AJS.$('<p>Please wait while we redirect you to your company log in page</p>').insertBefore(loginForm);
                        window.location.href = AJS.contextPath() + '/plugins/servlet/saml/auth';

                    } else {
                        loginForm.show();
                    }
                }
            });

        }
    }

});