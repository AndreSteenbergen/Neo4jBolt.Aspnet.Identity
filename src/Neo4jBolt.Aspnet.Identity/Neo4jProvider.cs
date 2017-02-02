using Neo4j.Driver.V1;

namespace Neo4jBolt.AspNet.Identity
{
    public sealed class Neo4jProvider
    {
        static volatile Neo4jProvider instance;
        static object syncRoot = new object();

        public IDriver Driver { get; private set; }

        Neo4jProvider(Configuration config)
        {
            var authToken = AuthTokens.Basic(config.Neo4jUser, config.Neo4jPassword);
            Driver = GraphDatabase.Driver(config.ConnectionString, authToken);

            //initialize always:
            using (var session = Driver.Session())
            using (var tx = session.BeginTransaction())
            {
                tx.Run($"CREATE CONSTRAINT ON (n:{config.UserLabel}) ASSERT n.Id IS UNIQUE");
                tx.Run($"CREATE CONSTRAINT ON (n:{config.UserLabel}) ASSERT n.UserName IS UNIQUE");
                tx.Run($"CREATE CONSTRAINT ON (n:{config.UserLabel}) ASSERT n.Email IS UNIQUE");

                tx.Run($"CREATE CONSTRAINT ON (n:{config.ClaimLabel}) ASSERT n.Unique IS UNIQUE");
                tx.Run($"CREATE CONSTRAINT ON (n:{config.UserLoginLabel}) ASSERT n.Unique IS UNIQUE");
                tx.Run($"CREATE CONSTRAINT ON (n:{config.UserTokenLabel}) ASSERT n.Unique IS UNIQUE");

                tx.Success();
            }
        }

        public static Neo4jProvider Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (syncRoot)
                    {
                        if (instance == null)
                            instance = new Neo4jProvider(Configuration.Instance);
                    }
                }

                return instance;
            }
        }
    }
}
