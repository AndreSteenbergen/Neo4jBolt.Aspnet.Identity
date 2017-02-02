using Microsoft.AspNetCore.Identity;
using Neo4j.Driver.V1;
using System.Collections.Generic;

namespace Neo4jBolt.AspNet.Identity.Mappers
{
    public static class UserLoginInfoMapper
    {
        public static Dictionary<string, object> ToDictionary(this UserLoginInfo info)
        {
            return new Dictionary<string, object> {
                { nameof(info.LoginProvider), info.LoginProvider },
                { nameof(info.ProviderDisplayName), info.ProviderDisplayName },
                { nameof(info.ProviderKey), info.ProviderKey },
                { "Unique", $"{info.LoginProvider}-<>-{info.ProviderKey}" }
            };
        }

        public static UserLoginInfo ToLogin(this INode node)
        {
            UserLoginInfo result;

            result = new UserLoginInfo(
                node.GetFromInode<string>(nameof(result.LoginProvider)),
                node.GetFromInode<string>(nameof(result.ProviderKey)),
                node.GetFromInode<string>(nameof(result.ProviderDisplayName))
            );

            return result;
        }
    }
}
