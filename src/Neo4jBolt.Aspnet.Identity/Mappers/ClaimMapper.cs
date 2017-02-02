using Neo4j.Driver.V1;
using System.Collections.Generic;
using System.Security.Claims;

namespace Neo4jBolt.AspNet.Identity.Mappers
{
    public static class ClaimMapper
    {
        public static Dictionary<string,object> ToDictionary(this Claim claim) {
            return new Dictionary<string, object> {
                { nameof(claim.Type), claim.Type },
                { nameof(claim.Value), claim.Value },
                { nameof(claim.Issuer), claim.Issuer },
                { nameof(claim.OriginalIssuer), claim.OriginalIssuer },
                { "Unique", $"{claim.Type}-<>-{claim.Value}-<>-{claim.Issuer}-<>-{claim.OriginalIssuer}" }
            };
        }

        public static Claim ToClaim(this INode node)
        {
            Claim result;

            result = new Claim(
                node.GetFromInode<string>(nameof(result.Type)),
                node.GetFromInode<string>(nameof(result.Value)),
                node.GetFromInode<string>(nameof(result.Issuer)),
                node.GetFromInode<string>(nameof(result.OriginalIssuer)));

            return result;
        }
    }
}
