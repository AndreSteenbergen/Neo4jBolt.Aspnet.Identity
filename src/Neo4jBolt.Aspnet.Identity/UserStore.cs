using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using System.Security.Claims;
using Neo4j.Driver.V1;
using Neo4jBolt.AspNet.Identity.Mappers;
using System.Globalization;

namespace Neo4jBolt.AspNet.Identity
{
    public class Neo4jUserStore<TUser> :
            IUserLoginStore<TUser>,
            IUserClaimStore<TUser>,
            IUserPasswordStore<TUser>,
            IUserSecurityStampStore<TUser>,
            IUserStore<TUser>,
            IUserAuthenticationTokenStore<TUser>,
            IUserEmailStore<TUser>,
            IUserLockoutStore<TUser>,
            IUserTwoFactorStore<TUser>,
            IUserPhoneNumberStore<TUser>
        where TUser : IdentityUser, new()
    {
        bool _disposed;

        void AddClaimsAsync(TUser user, IEnumerable<Claim> claims, ITransaction tx)
        {
            Configuration cfg = Configuration.Instance;
            var claimsArray = claims.Select(c => c.ToDictionary()).ToArray();
            tx.Run($@"
                    UNWIND {{claims}} AS cl
                    MATCH (user:{cfg.UserLabel} {{Id : {{userId}}}})
                    MERGE (claim:{cfg.ClaimLabel} {{Unique : cl.Unique}})
                    SET claim = cl
                    CREATE UNIQUE (user)-[:{cfg.HasClaimRelName}]->(claim)
                ",
                new Dictionary<string, object> { { "userId", user.Id }, { "claims", claimsArray } });
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                AddClaimsAsync(user, claims, tx);
                tx.Success();
            }
            return Task.FromResult(0);
        }

        void AddLoginAsync(TUser user, UserLoginInfo login, ITransaction tx)
        {
            Configuration cfg = Configuration.Instance;
            tx.Run($@"
                    WITH {{logininfo}} AS info
                    MATCH (user:{cfg.UserLabel} {{Id : {{userId}}}})
                    MERGE (userlogin:{cfg.UserLoginLabel} {{Unique : info.Unique}})
                    SET userlogin = info
                    CREATE UNIQUE (user)-[:{cfg.HasLoginRelName}]->(userlogin)
                ",
                new Dictionary<string, object> { { "userId", user.Id }, { "logininfo", login.ToDictionary() } });
        }

        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                AddLoginAsync(user, login, tx);
                tx.Success();
            }
            return Task.FromResult(0);
        }

        public Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                if (string.IsNullOrWhiteSpace(user.Id))
                    user.Id = Guid.NewGuid().ToString();

                try
                {
                    //creeer gebruiker
                    tx.Run($@"CREATE (u:{cfg.UserLabel} {{user}})", new Dictionary<string, object> { { "user", user.ToDictionary() } });
                    AddClaimsAsync(user, user.Claims, tx);

                    foreach (var login in user.Logins)
                        AddLoginAsync(user, new UserLoginInfo(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName), tx);

                    foreach (var token in user.Tokens)
                        SetTokenAsync(user, token.LoginProvider, token.Name, token.Value, tx);

                    tx.Success();

                    result = IdentityResult.Success;
                }
                catch
                {
                    result = IdentityResult.Failed();
                }
            }

            return Task.FromResult(result);
        }

        public Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                try
                {
                    tx.Run($@"
                             MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})
                             OPTIONAL MATCH (u)-[cr:{cfg.HasClaimRelName}]->(c)
                             OPTIONAL MATCH (u)-[lr:{cfg.HasLoginRelName}]->(l)
                             OPTIONAL MATCH (u)-[tr:{cfg.HasTokenRelName}]->(t)
                             DELETE u, cr, lr, tr", new { userId = user.Id });

                    tx.Run($@"MATCH(tkn:{ cfg.UserTokenLabel})
                              WHERE NOT ()-->(tkn)
                              DELETE tkn");

                    tx.Run($@"MATCH(login:{ cfg.UserLoginLabel})
                              WHERE NOT ()-->(login)
                              DELETE login");

                    tx.Run($@"MATCH(claim:{ cfg.ClaimLabel})
                              WHERE NOT ()-->(claim)
                              DELETE claim");

                    tx.Success();

                    result = IdentityResult.Success;
                }
                catch
                {
                    result = IdentityResult.Failed();
                }
            }
            return Task.FromResult(result);
        }

        IList<Claim> GetClaimsForUserById(string userId, ISession session)
        {
            Configuration cfg = Configuration.Instance;
            //get relations:
            var claims = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[cr:{cfg.HasClaimRelName}]->(c)
                             RETURN c
                           ", new { userId }).ToList();

            return claims.Select(c => c["c"].As<INode>().ToClaim()).ToList();
        }

        IList<IdentityUserToken> GetTokensForUserById(string userId, ISession session)
        {
            Configuration cfg = Configuration.Instance;
            //get relations:
            var tokens = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[tr:{cfg.HasTokenRelName}]->(t)
                             RETURN t
                           ", new { userId }).ToList();

            return tokens.Select(c => c["t"].As<INode>().ToToken()).ToList();
        }

        IList<UserLoginInfo> GetLoginsForUserById(string userId, ISession session)
        {
            Configuration cfg = Configuration.Instance;
            //get relations:
            var logins = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[lr:{cfg.HasLoginRelName}]->(l)
                             RETURN l
                           ", new { userId }).ToList();

            return logins.Select(c => c["l"].As<INode>().ToLogin()).ToList();
        }


        Tuple<
            IList<Claim>,
            IList<UserLoginInfo>,
            IList<IdentityUserToken>> GetRelationsForUserById(string userId, ISession session)
        {
            return new Tuple<IList<Claim>, IList<UserLoginInfo>, IList<IdentityUserToken>>(
                GetClaimsForUserById(userId, session),
                GetLoginsForUserById(userId, session),
                GetTokensForUserById(userId, session)
            );
        }

        public Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            TUser u = null;
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                var result = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{NormalizedEmail: {{ normalizedEmail}}}})
                             RETURN u
                           ", new { normalizedEmail }).ToList().FirstOrDefault();

                if (result != null)
                {
                    u = result["u"].As<INode>().ToUser<TUser>();

                    var relations = GetRelationsForUserById(u.Id, session);

                    foreach (var item in relations.Item1) u.Claims.Add(item);
                    foreach (var item in relations.Item2) u.Logins.Add(item);
                    foreach (var item in relations.Item3) u.Tokens.Add(item);
                }
            }

            return Task.FromResult(u);
        }

        public Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            TUser u = null;
            
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                var result = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{Id: {{ userId}}}})
                             RETURN u
                           ", new { userId }).ToList().FirstOrDefault();

                if (result != null)
                {
                    u = result["u"].As<INode>().ToUser<TUser>();
                    var relations = GetRelationsForUserById(u.Id, session);

                    foreach (var item in relations.Item1) u.Claims.Add(item);
                    foreach (var item in relations.Item2) u.Logins.Add(item);
                    foreach (var item in relations.Item3) u.Tokens.Add(item);
                }
            }

            return Task.FromResult(u);
        }

        public Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            TUser u = null;
            
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                var result = session.Run($@"
                             MATCH (u:{cfg.UserLabel})-[:{cfg.HasLoginRelName}]->(login:{cfg.UserLoginLabel} {{ LoginProvider: {{loginProvider}}, ProviderKey: {{providerKey}} }})
                             RETURN u
                           ", new { loginProvider, providerKey }).ToList().FirstOrDefault();

                if (result != null)
                {
                    u = result["u"].As<INode>().ToUser<TUser>();
                    var relations = GetRelationsForUserById(u.Id, session);

                    foreach (var item in relations.Item1) u.Claims.Add(item);
                    foreach (var item in relations.Item2) u.Logins.Add(item);
                    foreach (var item in relations.Item3) u.Tokens.Add(item);
                }
            }

            return Task.FromResult(u);
        }

        public Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            TUser u = null;
            
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                var result = session.Run($@"
                             MATCH (u:{cfg.UserLabel} {{NormalizedUserName: {{ normalizedUserName}}}})
                             RETURN u
                           ", new { normalizedUserName }).ToList().FirstOrDefault();

                if (result != null)
                {
                    u = result["u"].As<INode>().ToUser<TUser>();

                    var relations = GetRelationsForUserById(u.Id, session);

                    foreach (var item in relations.Item1) u.Claims.Add(item);
                    foreach (var item in relations.Item2) u.Logins.Add(item);
                    foreach (var item in relations.Item3) u.Tokens.Add(item);
                }
            }

            return Task.FromResult(u);
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IList<Claim> result;

            var neo4jDriver = Neo4jProvider.Instance.Driver;
            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                result = GetClaimsForUserById(user.Id, session);
            }

            return Task.FromResult(result);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IList<UserLoginInfo> result;

            var neo4jDriver = Neo4jProvider.Instance.Driver;
            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                result = GetLoginsForUserById(user.Id, session);
            }

            return Task.FromResult(result);
        }
        
        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.LockoutEnd);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.NormalizedEmail);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PasswordHash);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.SecurityStamp);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(user.UserName);
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
        }

        void AddRelationsToUsers(Dictionary<string, TUser> users, ISession session)
        {
            var userIds = users.Keys.ToArray();

            Configuration cfg = Configuration.Instance;
            //get relations:
            var claims = session.Run($@"
                             UNWIND {{userIds}} as userId
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[cr:{cfg.HasClaimRelName}]->(c)
                             RETURN userId, c
                           ", new { userIds }).ToList();

            foreach (var c in claims)
            {
                var claim = c["c"].As<INode>().ToClaim();
                var userId = c["userId"].As<string>();
                users[userId].Claims.Add(claim);
            }

            var tokens = session.Run($@"
                             UNWIND {{userIds}} as userId
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[tr:{cfg.HasTokenRelName}]->(t)
                             RETURN userId, t
                           ", new { userIds }).ToList();

            foreach (var tkn in tokens)
            {
                var token = tkn["t"].As<INode>().ToToken();
                var userId = tkn["userId"].As<string>();
                users[userId].Tokens.Add(token);
            }

            var logins = session.Run($@"
                             UNWIND {{userIds}} as userId
                             MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                             MATCH (u)-[lr:{cfg.HasLoginRelName}]->(l)
                             RETURN userId, l
                           ", new { userIds }).ToList();

            foreach (var l in logins)
            {
                var login = l["l"].As<INode>().ToLogin();
                var userId = l["userId"].As<string>();
                users[userId].Logins.Add(login);
            }
        }

        public Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IList<TUser> result = new List<TUser>();
            
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Read))
            {
                var usersMatching = session.Run($@"
                             MATCH (u:{cfg.UserLabel})-[:{cfg.HasClaimRelName}]->(c {{`Type`: {{type}}, Value : {{value}}}})
                             RETURN DISTINCT u
                           ", new { claim.Type, claim.Value }).ToList().Select(u => u["u"].As<INode>().ToUser<TUser>()).ToDictionary(usr => usr.Id);

                AddRelationsToUsers(usersMatching, session);
                result = usersMatching.Values.ToList();
            }

            return Task.FromResult(result);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                tx.Run($@"UNWIND {{claims}} as cl
                          MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})-[cr:{cfg.HasClaimRelName}]->(c {{Unique : cl.Unique}})
                          DELETE cr", new { userId = user.Id, claims = claims.Select(c => c.ToDictionary()).ToArray() });

                tx.Run($@"MATCH (claim:{cfg.ClaimLabel})
                          WHERE NOT ()-->(claim)
                          DELETE claim");

                tx.Success();
            }
            return Task.FromResult(result);
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                tx.Run($@"WITH {{login}} as ll
                          MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})-[lr:{cfg.HasLoginRelName}]->(l {{LoginProvider : ll.loginProvider, ProviderKey : ll.providerKey}})
                          DELETE lr", new { userId = user.Id, login = new Dictionary<string, object>{ { "loginProvider", loginProvider }, { "providerKey", providerKey } } });

                tx.Run($@"MATCH (login:{cfg.HasLoginRelName})
                          WHERE NOT ()-->(login)
                          DELETE login");

                tx.Success();
            }
            return Task.FromResult(result);
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                tx.Run($@"WITH {{claim}} as cl
                          MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})-[cr:{cfg.HasClaimRelName}]->(c {{Unique : cl.Unique}})
                          DELETE cr

                          WITH {{newClaim}} as new                      
                          MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})
                          MERGE (claim:{cfg.ClaimLabel} {{Unique : cl.Unique}})
                          SET claim = cl
                          CREATE UNIQUE (user)-[:{cfg.HasClaimRelName}]->(claim)", new { userId = user.Id, claim = claim.ToDictionary(), newClaim = newClaim.ToDictionary() });

                tx.Run($@"MATCH (claim:{cfg.ClaimLabel})
                          WHERE NOT ()-->(claim)
                          DELETE claim");

                tx.Success();
            }
            return Task.FromResult(result);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.Email = email;
            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEnd = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.NormalizedUserName = normalizedName;
            return Task.FromResult(0);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.UserName = userName;
            return Task.FromResult(0);
        }

        public Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            user.ConcurrencyStamp = Guid.NewGuid().ToString();
            var userDictionary = user.ToDictionary();

            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            IdentityResult result = null;
            Configuration cfg = Configuration.Instance;
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                var r = tx.Run($@"MATCH (n:{cfg.UserLabel} {{Id : {{userId}}}}) RETURN n.Id AS Id", new { userId = user.Id }).ToList();
                if (r.Any())
                {
                    tx.Run($@"MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}}) SET u = {{ user }}", new { userId = user.Id, user = user.ToDictionary() });
                    
                    tx.Success();
                    result = IdentityResult.Success;
                }
                else
                {
                    result = IdentityResult.Failed();
                }
            }

            return Task.FromResult(result);
        }
        
        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        public void Dispose()
        {
            _disposed = true;
        }


        void SetTokenAsync(TUser user, string loginProvider, string name, string value, ITransaction tx)
        {
            Configuration cfg = Configuration.Instance;
            IdentityUserToken tk = new IdentityUserToken { LoginProvider = loginProvider, Name = name, Value = value };
            var dict = tk.ToDictionary();

            tx.Run($@"
                WITH {{token}} AS tkn
                MERGE (tk:{cfg.UserTokenLabel} {{Unique: tk.Unique}})
                ON MATCH SET tk = token
                MATCH (u:{cfg.UserLabel} {{Id: {{userId}}}})
                CREATE UNIQUE (u)-[:{cfg.HasTokenRelName}]->(tk)
            ", new { userId = user.Id, token = dict });
        }

        public Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            var neo4jDriver = Neo4jProvider.Instance.Driver;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                SetTokenAsync(user, loginProvider, name, value, tx);
                tx.Success();
            }
            return Task.FromResult(0);
        }

        public Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var neo4jDriver = Neo4jProvider.Instance.Driver;
            Configuration cfg = Configuration.Instance;

            using (var session = neo4jDriver.Session(AccessMode.Write))
            using (var tx = session.BeginTransaction())
            {
                tx.Run($@"MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})
                          MATCH (u)-[tr:{cfg.HasTokenRelName}]->(t {{LoginProvider : {{loginProvider}}, Name : {{name}}}})
                          DELETE tr", new { userId = user.Id, loginProvider, name });

                tx.Run($@"MATCH (tkn:{cfg.UserTokenLabel})
                          WHERE NOT ()-->(tkn)
                          DELETE tkn");
                
                tx.Success();
            }
            return Task.FromResult(0);
        }

        public Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var neo4jDriver = Neo4jProvider.Instance.Driver;
            Configuration cfg = Configuration.Instance;

            string value = null;
            using (var session = neo4jDriver.Session(AccessMode.Write))
            {
                var result = session.Run($@"MATCH (u:{cfg.UserLabel} {{Id : {{userId}}}})-[tr:{cfg.HasTokenRelName}]->(t {{LoginProvider : {{loginProvider}}, Name : {{name}}}})
                                            RETURN t.Value", new { userId = user.Id, loginProvider, name }).ToList().FirstOrDefault();

                value = result["t.Value"].As<string>();
            }
            return Task.FromResult(value);
        }
    }
}
