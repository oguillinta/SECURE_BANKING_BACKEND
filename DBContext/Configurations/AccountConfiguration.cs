using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ApiSecureBank.DBContext.Configurations
{
    public class AccountConfiguration : IEntityTypeConfiguration<Account>
    {
        public void Configure(EntityTypeBuilder<Account> builder)
        {
            // Explicitly maps the entity to the 'Account' table in the database.
            builder.ToTable("Account");

            // You can add other configurations here, for example:
            // builder.HasKey(a => a.Id);
            // builder.Property(a => a.AccountNumber).IsRequired();
        }
    }
}
