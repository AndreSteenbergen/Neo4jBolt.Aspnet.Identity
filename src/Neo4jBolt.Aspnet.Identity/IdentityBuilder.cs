using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Reflection;

namespace Neo4jBolt.AspNet.Identity
{
    /// <summary>
    /// Helper functions for configuring identity services.
    /// </summary>
    public class IdentityBuilder
    {
        /// <summary>
        /// Creates a new instance of <see cref="IdentityBuilder"/>.
        /// </summary>
        /// <param name="user">The <see cref="Type"/> to use for the users.</param>
        /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
        public IdentityBuilder(Type user, IServiceCollection services)
        {
            UserType = user;
            Services = services;
        }

        /// <summary>
        /// Gets the <see cref="Type"/> used for users.
        /// </summary>
        /// <value>
        /// The <see cref="Type"/> used for users.
        /// </value>
        public Type UserType { get; private set; }

        /// <summary>
        /// Gets the <see cref="IServiceCollection"/> services are attached to.
        /// </summary>
        /// <value>
        /// The <see cref="IServiceCollection"/> services are attached to.
        /// </value>
        public IServiceCollection Services { get; private set; }

        private IdentityBuilder AddScoped(Type serviceType, Type concreteType)
        {
            Services.AddScoped(serviceType, concreteType);
            return this;
        }

        /// <summary>
        /// Adds an <see cref="IUserValidator{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="T">The user validator type.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserValidator<T>() where T : class
        {
            return AddScoped(typeof(IUserValidator<>).MakeGenericType(UserType), typeof(T));
        }

        /// <summary>
        /// Adds an <see cref="IUserClaimsPrincipalFactory{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="T">The type of the claims principal factory.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddClaimsPrincipalFactory<T>() where T : class
        {
            return AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(T));
        }

        /// <summary>
        /// Adds an <see cref="IdentityErrorDescriber"/>.
        /// </summary>
        /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
        {
            Services.AddScoped<IdentityErrorDescriber, TDescriber>();
            return this;
        }

        /// <summary>
        /// Adds an <see cref="IPasswordValidator{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="T">The user type whose password will be validated.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddPasswordValidator<T>() where T : class
        {
            return AddScoped(typeof(IPasswordValidator<>).MakeGenericType(UserType), typeof(T));
        }

        /// <summary>
        /// Adds an <see cref="IUserStore{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="T">The user type whose password will be validated.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserStore<T>() where T : class
        {
            return AddScoped(typeof(IUserStore<>).MakeGenericType(UserType), typeof(T));
        }

        /// <summary>
        /// Adds a token provider.
        /// </summary>
        /// <typeparam name="TProvider">The type of the token provider to add.</typeparam>
        /// <param name="providerName">The name of the provider to add.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddTokenProvider<TProvider>(string providerName) where TProvider : class
        {
            return AddTokenProvider(providerName, typeof(TProvider));
        }

        /// <summary>
        /// Adds a token provider for the <seealso cref="UserType"/>.
        /// </summary>
        /// <param name="providerName">The name of the provider to add.</param>
        /// <param name="provider">The type of the <see cref="IUserTwoFactorTokenProvider{TUser}"/> to add.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddTokenProvider(string providerName, Type provider)
        {
            if (!typeof(IUserTwoFactorTokenProvider<>).MakeGenericType(UserType).GetTypeInfo().IsAssignableFrom(provider.GetTypeInfo()))
            {
                throw new InvalidOperationException(string.Format(Resources.InvalidManagerType, provider.Name, "IUserTokenProvider", UserType.Name));
            }
            Services.Configure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);
            });
            Services.AddTransient(provider);
            return this;
        }

        /// <summary>
        /// Adds the default token providers used to generate tokens for reset passwords, change email
        /// and change telephone number operations, and for two factor authentication token generation.
        /// </summary>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddDefaultTokenProviders()
        {
            var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(UserType);
            var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(UserType);
            var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(UserType);
            return AddTokenProvider(TokenOptions.DefaultProvider, dataProtectionProviderType)
                .AddTokenProvider(TokenOptions.DefaultEmailProvider, emailTokenProviderType)
                .AddTokenProvider(TokenOptions.DefaultPhoneProvider, phoneNumberProviderType);
        }

        /// <summary>
        /// Adds a <see cref="UserManager{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="TUserManager">The type of the user manager to add.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserManager<TUserManager>() where TUserManager : class
        {
            var userManagerType = typeof(UserManager<>).MakeGenericType(UserType);
            var customType = typeof(TUserManager);
            if (userManagerType == customType ||
                !userManagerType.GetTypeInfo().IsAssignableFrom(customType.GetTypeInfo()))
            {
                throw new InvalidOperationException(string.Format(Resources.InvalidManagerType, customType.Name, "UserManager", UserType.Name));
            }
            Services.AddScoped(customType, services => services.GetRequiredService(userManagerType));
            return AddScoped(userManagerType, customType);
        }

        /// <summary>
        /// Adds a <see cref="SignInManager{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="TSignInManager">The type of the sign in manager to add.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddSignInManager<TSignInManager>() where TSignInManager : class
        {
            var managerType = typeof(SignInManager<>).MakeGenericType(UserType);
            var customType = typeof(TSignInManager);
            if (managerType == customType ||
                !managerType.GetTypeInfo().IsAssignableFrom(customType.GetTypeInfo()))
            {
                throw new InvalidOperationException(string.Format(Resources.InvalidManagerType, customType.Name, "SignInManager", UserType.Name));
            }
            Services.AddScoped(typeof(TSignInManager), services => services.GetRequiredService(managerType));
            return AddScoped(managerType, typeof(TSignInManager));
        }
    }
}
