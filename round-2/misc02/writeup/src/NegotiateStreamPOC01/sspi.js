const AcquireCredentialsHandleW = Module.getExportByName(null, 'AcquireCredentialsHandleW');
const AcceptSecurityContext = Module.getExportByName(null, 'AcceptSecurityContext');
const InitializeSecurityContextW = Module.getExportByName(null, 'InitializeSecurityContextW');
const ImpersonateSecurityContext = Module.getExportByName(null, 'ImpersonateSecurityContext');
console.log('AcquireCredentialsHandleW @ ' + AcquireCredentialsHandleW);
console.log('AcceptSecurityContext @ ' + AcceptSecurityContext);
console.log('InitializeSecurityContextW @ ' + InitializeSecurityContextW);
console.log('ImpersonateSecurityContext @ ' + ImpersonateSecurityContext);

Interceptor.attach(AcquireCredentialsHandleW, {
    onEnter: function (args) {
        console.log("AcquireCredentialsHandleW()");
    }
});

Interceptor.attach(AcceptSecurityContext, {
    onEnter: function (args) {
        console.log("AcceptSecurityContext()");
    }
});

Interceptor.attach(InitializeSecurityContextW, {
    onEnter: function (args) {
        console.log("InitializeSecurityContextW()");
    }
});

Interceptor.attach(ImpersonateSecurityContext, {
    onEnter: function (args) {
        console.log("ImpersonateSecurityContext()");
    }
});