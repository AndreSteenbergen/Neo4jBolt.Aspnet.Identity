using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;

namespace Neo4jBolt.AspNet.Identity
{
    public static class IdentityNeo4jBuilderExtensions
    {
        public static IdentityBuilder AddIdentity<TUser>(
            this IServiceCollection services)
            where TUser : class
        {
            return services.AddIdentity<TUser>(setupAction: null);
        }

        /// <summary>
        /// Adds and configures the identity system for the specified User and Role types.
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentity<TUser>(
            this IServiceCollection services,
            Action<IdentityOptions> setupAction)
            where TUser : class            
        {
            // Services used by identity
            services.AddAuthentication(options =>
            {
                // This is the Default value for ExternalCookieAuthenticationScheme
                options.SignInScheme = new IdentityCookieOptions().ExternalCookieAuthenticationScheme;
            });

            // Hosting doesn't add IHttpContextAccessor by default
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            // Identity services
            services.TryAddSingleton<IdentityMarkerService>();
            services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
            services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            
            // No interface for the error describer so we can add errors without rev'ing the interface
            services.TryAddScoped<IdentityErrorDescriber>();
            services.TryAddScoped<ISecurityStampValidator, SecurityStampValidator<TUser>>();
            services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, UserClaimsPrincipalFactory<TUser>>();
            services.TryAddScoped<UserManager<TUser>, UserManager<TUser>>();
            services.TryAddScoped<SignInManager<TUser>, SignInManager<TUser>>();
            
            if (setupAction != null)
            {
                services.Configure(setupAction);
            }

            return new IdentityBuilder(typeof(TUser), services);
        }

        public static IdentityBuilder AddNeo4jStores(this IdentityBuilder builder)
        {
            builder.Services.TryAdd(GetDefaultServices(builder.UserType));
            return builder;
        }

        public static IdentityBuilder AddIdentityServerUserClaimsPrincipalFactory(this IdentityBuilder builder)
        {
            var interfaceType = typeof(IUserClaimsPrincipalFactory<>);
            interfaceType = interfaceType.MakeGenericType(builder.UserType);

            var classType = typeof(UserClaimsPrincipalFactory<>);
            classType = classType.MakeGenericType(builder.UserType);

            builder.Services.AddScoped(interfaceType, classType);

            return builder;
        }

        static IServiceCollection GetDefaultServices(Type userType)
        {
            Type userStoreType;
            userStoreType = typeof(Neo4jUserStore<>).MakeGenericType(userType);
            
            var services = new ServiceCollection();
            services.AddScoped(
                typeof(IUserStore<>).MakeGenericType(userType),
                userStoreType);

            return services;
        }
    }
}
