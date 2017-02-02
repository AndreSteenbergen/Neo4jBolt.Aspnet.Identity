# Neo4jBolt.Aspnet.Identity
Identity provider using the Neo4j Bolt driver.

In the appsettings.json:
```
{
  "Neo4j": {
    "Connection": {
      "Uri": "bolt://localhost:7687",
      "Username": "neo4j",
      "Password": "neo4j"
    }
  }
}
```


Difference with the entityframework backed provider:

```
//first initialize neo4j configuration
            NameValueCollection collection = new NameValueCollection();
            foreach (var kvPair in Configuration.GetSection("Neo4j").AsEnumerable())
            {
                if (kvPair.Key.StartsWith("Neo4j:"))
                    collection.Set(kvPair.Key.Remove(0, 6), kvPair.Value);
            }
Neo4jBolt.AspNet.Identity.Configuration.SetConfiguration(collection);

services.AddIdentity<ApplicationUser>()
                    .AddNeo4jStores()
                    .AddDefaultTokenProviders()
                    .AddIdentityServerUserClaimsPrincipalFactory();
```
