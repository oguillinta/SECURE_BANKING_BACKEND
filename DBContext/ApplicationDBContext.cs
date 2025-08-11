﻿using Microsoft.EntityFrameworkCore;

namespace ApiSecureBank.DBContext
{
    public class ApplicationDBContext : DbContext
    {
        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options) : base(options)
        {
        }
        public DbSet<Entities.InterestRate> InterestRates { get; set; } 
        public DbSet<Entities.Account> Accounts { get; set; }
        public DbSet<Entities.Customer> Customers { get; set; }

        public DbSet<Entities.AccountSummaryReport> AccountSummaryReports { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Esta línea escanea todo el ensamblado en busca de clases que implementen IEntityTypeConfiguration
            // y aplica sus configuraciones automáticamente. Mantiene este archivo limpio.
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDBContext).Assembly);
        }
    }
}
