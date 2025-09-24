<#import "login.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section == "title">
        Service2 verification
    <#elseif section == "header">
        Verify Service2 credentials
    <#elseif section == "form">
        <form id="kc-s2-basic-auth-form" class="kc-form" action="${url.loginAction}" method="post">
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="s2-username">Service2 username</label>
                <input id="s2-username" name="s2-username" type="text" class="pf-c-form-control" value="${s2Username!}" autofocus>
            </div>
            <div class="pf-c-form__group">
                <label class="pf-c-form__label" for="s2-password">Service2 password</label>
                <input id="s2-password" name="s2-password" type="password" class="pf-c-form-control">
            </div>
            <div class="pf-c-form__group pf-m-action">
                <button class="pf-c-button pf-m-primary" type="submit" id="kc-login" name="login">Continue</button>
            </div>
        </form>
    <#elseif section == "info">
        <p>Credentials are validated by calling <strong>${s2BaseUrl!}${s2Path!""}</strong>.</p>
        <p>Provide the HTTP Basic Auth credentials that grant access to Service2's protected endpoint.</p>
    </#if>
</@layout.registrationLayout>
