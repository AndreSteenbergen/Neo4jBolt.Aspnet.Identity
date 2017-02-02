using System;
using System.Collections.Specialized;

namespace Neo4jBolt.AspNet.Identity
{
    public class Configuration
    {
        static volatile Configuration instance;
        static object syncRoot = new object();

        NameValueCollection Settings;

        /// <summary>
        /// Initializes a new instance of the <see cref="Configuration"/> class.
        /// </summary>
        /// <param name="settings">The settings used to define the labels</param>
        Configuration(NameValueCollection settings)
        {
            if (settings == null)
            {
                throw new ArgumentNullException(nameof(settings), "Unable to find or read Neo4j configuration");
            }
            Settings = settings;
        }
        
        public string ConnectionString => Settings["Connection:Uri"];
        public string Neo4jUser => Settings["Connection:Username"];
        public string Neo4jPassword => Settings["Connection:Password"];

        public string UserLabel => Settings["UserLabel"] ?? "User";
        public string ClaimLabel => Settings["ClaimLabel"] ?? "Claim";
        public string UserLoginLabel => Settings["UserLoginLabel"] ?? "UserLogin";
        public string UserTokenLabel => Settings["UserTokenLabel"] ?? "UserToken";

        public string HasClaimRelName => Settings["HasClaimRelName"] ?? "HAS_Claim";
        public string HasLoginRelName => Settings["HasLoginRelName"] ?? "HAS_Login";
        public string HasTokenRelName => Settings["HasTokenRelName"] ?? "HAS_Token";
        

        public string AuthProviderName => Settings["AuthProviderName"] ?? "IdentityServer4";

        public static Configuration SetConfiguration(NameValueCollection settings)
        {
            lock (syncRoot)
            {
                instance = new Configuration(settings);
            }
            return instance;    
        }

        /// <summary>
        /// Global singleton for accessing common graph configuration settings
        /// </summary>
        public static Configuration Instance
        {
            get
            {
                if (instance == null)
                    throw new Exception("Neo4J is not yet configured");
                
                return instance;
            }
        }
    }
}
