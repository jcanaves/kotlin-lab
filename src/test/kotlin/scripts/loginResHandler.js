client.assert(typeof response.body.token !== "undefined", "No token returned");
client.global.set("auth_token", response.body.token);
