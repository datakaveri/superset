## <center>GMAS Superset</center>

1. Setting up Superset

   1. For Mapbox, create a mapbox token in https://www.mapbox.com/, and add it to MAPBOX_API_KEY present in <code>< your-superset-folder >/docker/.env</code> file
   2. You can bring up superset by running `docker-compose up -d` and access the UI in `localhost:8088`. Credentials are `username: admin, password: admin`
   3. To add custom Keycloak authorization, change the values in `<your-superset-folder>/docker/pythonpath-dev/client-secret.json` file

   ```json
   {
     "<myOpenIDProvider>": {
       "issuer": "https://<your-keycloak-domain>/auth/realms/<your-keycloak-realm-name>",
       "auth_uri": "https://<your-keycloak-domain>/auth/realms/<your-keycloak-realm-name>/protocol/openid-connect/auth",
       "client_id": "<your-keycloak-client>",
       "client_secret": "<your-keycloak-client-secret>",
       "post_logout_redirect_uri": ["<your-superset-url>"],
       "userinfo_uri": "https://<your-keycloak-domain>/auth/realms/<your-keycloak-realm-name>/openid-connect/userinfo",
       "token_uri": "<your-token-url>",
       "token_introspection_uri": "https://<your-keycloak-domain>/auth/realms/<your-keycloak-realm-name>/protocol/openid-connect/token/introspect"
     }
   }
   ```

2. To enable embedding superset dashboards in external applications
   1. You will require a guest-token, for which we have a microservice that will generate it. You can clone the repository from here - <link>https://github.com/datakaveri/gra-superset-guesttoken-middlware</link>
   2. You can use the following API to fetch the guest token, and use an embedded sdk (<link>https://www.npmjs.com/package/@superset-ui/embedded-sdk</link>) to embed the dashboard iframe.
   ```bash
   curl --request POST \
   --url https://dashboard.idxgh.com/middleware/guest_token/ \
   --data '{
        "access_token": “<insert-keycloak-access-token>”,
        "dashboard_id": “<insert-dashboard-id>”
   }'
   ```
