export function login(backendUri: string) {
    const response_type = "token%20id_token";
    const scope = "openid%20laundry%20amenities";
    const nonce = "nonce";
    const grant_type = "implicit";
    const redirect_uri = "http://localhost:5173/";

    fetch(`${backendUri}/api/v1/creds`).then(
        (response) => response.json().then(
            (json) => {
                const client_id = json.client_id;
                const x = new XMLHttpRequest();
                fetch(
                    `${backendUri}/openid/authentication?response_type=${response_type}&client_id=${client_id}&scope=${scope}&redirect_uri=${redirect_uri}&grant_type=${grant_type}&nonce=${nonce}`,
                ).then((response) => {
                    const access_token_re = /access_token=[^&]+/;
                    response.body?.getReader().read().then((body) => {
                        const bodyString = new TextDecoder().decode(body.value);
                        const access_token = access_token_re
                            .exec(bodyString)?.[0]
                            .split("=")[1];
                        console.log(`ACCESS TOKEN: ${access_token}`);
                        sessionStorage.setItem("accessToken", access_token!);
                        sessionStorage.setItem("admin", "0");
                        document.location.reload();
                    });
                });
            }
        )
    );
}

export function loggedIn() {
    return sessionStorage.getItem("accessToken") !== null;
}

export function isAdmin() {
    return sessionStorage.getItem("admin") == "1";
}

export function populateLaundriesAndAmenities(backendUri: string) {
    let laundries: any[] = [];
    let amenities: any[] = [];

    fetch(
        `${backendUri}/api/v1/laundry`,
        {
            headers: {
                "Authorization": `Bearer ${sessionStorage.getItem("accessToken")}`,
                "Host": `${backendUri}`
            }
        }
    ).then(async (l) => {
            laundries = eval(
                new TextDecoder().decode(
                    (await l.body?.getReader().read())?.value)
                );
            sessionStorage.setItem("laundries", JSON.stringify(laundries));
        }
        );

    fetch(
        `${backendUri}/api/v1/amenities`,
        {
            headers: {
                "Authorization": `Bearer ${sessionStorage.getItem("accessToken")}`,
                "Host": `${backendUri}`
            }
        }
    ).then(async (a) => {
            amenities = eval(
                new TextDecoder().decode(
                    (await a.body?.getReader().read())?.value)
            );
            sessionStorage.setItem("amenities", JSON.stringify(amenities));
        }
        );
}

export function generateReport(backendUri: string) {
    fetch(
        `${backendUri}/api/v1/generate-report`,
        {
            headers: {
                "Authorization": `Bearer ${sessionStorage.getItem("accessToken")}`,
                "Host": `${backendUri}`,
                "Content-Type": "application/json"
            },
            method: "POST",
            body: "{}",
        }
    ).catch(
        err => console.log(err)
    )
    .then( res => res?.blob() )
    .then( blob => {
      if (blob === undefined || blob.type === "application/json") return;
      var file = window.URL.createObjectURL(blob);
      window.location.assign(file);
    });
}

export function logout() {
    sessionStorage.clear();
    document.location.reload();
}

export * as utils from './utils';