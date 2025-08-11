using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ApiSecureBank.DBContext.Configurations
{
    public class InterestRateConfiguration : IEntityTypeConfiguration<InterestRate>
    {
        public void Configure(EntityTypeBuilder<InterestRate> builder)
        {
            builder.ToTable("InterestRate");

            // builder.HasKey(i => i.Id);
        }
    }
}
