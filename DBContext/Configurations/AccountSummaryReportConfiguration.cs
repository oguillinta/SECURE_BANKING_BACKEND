using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ApiSecureBank.DBContext.Configurations
{
    public class AccountSummaryReportConfiguration : IEntityTypeConfiguration<AccountSummaryReport>
    {
        public void Configure(EntityTypeBuilder<AccountSummaryReport> builder)
        {
            // Explicitly maps the entity to the 'AccountSummaryReport' table in the database.
            builder.ToTable("AccountSummaryReport");

            // You can add other configurations here, for example:
            // builder.HasKey(a => a.Id);
            // builder.Property(a => a.AccountNumber).IsRequired();
        }
    }
}
