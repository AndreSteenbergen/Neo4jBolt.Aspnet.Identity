using Neo4j.Driver.V1;
using System.Collections.Generic;

namespace Neo4jBolt.AspNet.Identity.Mappers
{
    public static class UserTokenMapper
    {
        public static Dictionary<string, object> ToDictionary(this IdentityUserToken token)
        {
            return new Dictionary<string, object> {
                { nameof(token.LoginProvider), token.LoginProvider },
                { nameof(token.Name), token.Name },
                { nameof(token.Value), token.Value },
                { "Unique", $"{token.LoginProvider}-<>-{token.Name}-<>-{token.Value}" }
            };
        }

        public static IdentityUserToken ToToken(this INode node)
        {
            IdentityUserToken result;

            result = new IdentityUserToken
            {
                LoginProvider = node.GetFromInode<string>(nameof(result.LoginProvider)),
                Name = node.GetFromInode<string>(nameof(result.Name)),
                Value = node.GetFromInode<string>(nameof(result.Value))
            };

            return result;
        }
    }
}
