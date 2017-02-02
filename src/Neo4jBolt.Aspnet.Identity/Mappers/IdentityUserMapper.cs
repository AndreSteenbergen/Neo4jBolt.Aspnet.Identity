using Neo4j.Driver.V1;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;

namespace Neo4jBolt.AspNet.Identity.Mappers
{
    public static class IdentityUserMapper
    {
        public static T GetFromInode<T>(this INode n, string property)
        {
            if (n.Properties.ContainsKey(property))
                return n[property].As<T>();

            return default(T);
        }

        public static Dictionary<string,object> ToDictionary<TUser>(this TUser usr) where TUser : IdentityUser, new() 
        {
            var result = new Dictionary<string, object> {
                { nameof(usr.Id), usr.Id },
                { nameof(usr.UserName), usr.UserName },
                { nameof(usr.AccessFailedCount), usr.AccessFailedCount },
                { nameof(usr.ConcurrencyStamp), usr.ConcurrencyStamp },
                { nameof(usr.Email), usr.Email },
                { nameof(usr.EmailConfirmed), usr.EmailConfirmed },
                { nameof(usr.LockoutEnabled), usr.LockoutEnabled },
                { nameof(usr.LockoutEnd), usr.LockoutEnd?.ToString("o") },
                { nameof(usr.NormalizedEmail), usr.NormalizedEmail },
                { nameof(usr.NormalizedUserName), usr.NormalizedUserName },
                { nameof(usr.PasswordHash), usr.PasswordHash },
                { nameof(usr.PhoneNumber), usr.PhoneNumber },
                { nameof(usr.PhoneNumberConfirmed), usr.PhoneNumberConfirmed },
                { nameof(usr.SecurityStamp), usr.SecurityStamp },
                { nameof(usr.TwoFactorEnabled), usr.TwoFactorEnabled }
            };

            //be aware the bolt driver might not like all properties!
            foreach (var prop in usr.GetType().GetProperties(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Instance))
            {
                result[prop.Name] = prop.GetValue(usr);
            }

            return result;
        }

        public static TUser ToUser<TUser>(this INode node) where TUser : IdentityUser, new()
        {
            TUser result;

            string s = node.GetFromInode<string>(nameof(result.LockoutEnd));
            DateTimeOffset? lockoutEnd = string.IsNullOrEmpty(s) ? (DateTimeOffset?)null : DateTimeOffset.ParseExact(s, "o", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

            result = new TUser
            {
                Id = node.GetFromInode<string>(nameof(result.Id)),
                UserName = node.GetFromInode<string>(nameof(result.UserName)),
                AccessFailedCount = node.GetFromInode<int>(nameof(result.AccessFailedCount)),
                ConcurrencyStamp = node.GetFromInode<string>(nameof(result.ConcurrencyStamp)),
                Email = node.GetFromInode<string>(nameof(result.Email)),
                EmailConfirmed = node.GetFromInode<bool>(nameof(result.EmailConfirmed)),
                LockoutEnabled = node.GetFromInode<bool>(nameof(result.LockoutEnabled)),
                LockoutEnd = lockoutEnd,
                NormalizedEmail = node.GetFromInode<string>(nameof(result.NormalizedEmail)),
                NormalizedUserName = node.GetFromInode<string>(nameof(result.NormalizedUserName)),
                PasswordHash = node.GetFromInode<string>(nameof(result.PasswordHash)),
                PhoneNumber = node.GetFromInode<string>(nameof(result.PhoneNumber)),
                PhoneNumberConfirmed = node.GetFromInode<bool>(nameof(result.PhoneNumberConfirmed)),
                SecurityStamp = node.GetFromInode<string>(nameof(result.SecurityStamp)),
                TwoFactorEnabled = node.GetFromInode<bool>(nameof(result.TwoFactorEnabled))
            };

            //also add all other properties from the TUser type
            //be aware the bolt driver might not like all properties!
            MethodInfo asMethod = typeof(ValueExtensions).GetMethod("As", BindingFlags.Public | BindingFlags.Static);
            foreach (var prop in result.GetType().GetProperties(BindingFlags.DeclaredOnly | BindingFlags.Public | BindingFlags.Instance))
            {
                if (node.Properties.ContainsKey(prop.Name))
                {
                    var genericAsMethod = asMethod.MakeGenericMethod(prop.GetType());
                    prop.SetValue(result, genericAsMethod.Invoke(null, new[] { node[prop.Name] }));
                }
            }

            return result;
        }
    }
}
