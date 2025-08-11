using ApiSecureBank.DBContext;
using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;

namespace ApiSecureBank.Repositories
{
    public class AccountSummaryReportRepository(ApplicationDBContext context,
        IHttpContextAccessor httpContextAccessor) : IAccountSummaryReportRepository
    {
        public async Task<List<AccountSummaryReport>> GetAll()
        {
            return await context.AccountSummaryReports
                .ToListAsync();
        }

        public async Task<int> Create(AccountSummaryReport accountSummaryReport)
        {
            context.Add(accountSummaryReport);
            await context.SaveChangesAsync();
            return accountSummaryReport.Id;
        }

        public async Task<AccountSummaryReport?> GetById(int id)
        {
            return await context.AccountSummaryReports
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<List<AccountSummaryReport>> GetByAccountType(string accountType)
        {
            return await context.AccountSummaryReports
                .Where(g => g.accountType == accountType)
                .ToListAsync();
        }

        public async Task<bool> Exist(int id)
        {
            return await context.AccountSummaryReports.AnyAsync(g => g.Id == id);
        }

        public async Task Update(AccountSummaryReport accountSummaryReport)
        {
            context.Update(accountSummaryReport);
            await context.SaveChangesAsync();
        }

        public async Task Delete(int id)
        {
            await context.AccountSummaryReports
                .Where(g => g.Id == id)
                .ExecuteDeleteAsync();
        }

        public async Task<List<AccountSummaryReport>> GetAccountsSummary()
        {
            return await context.AccountSummaryReports
                .OrderByDescending(g => g.totalBalance)
                .ToListAsync();
        }

        public async Task<AccountSummaryReport?> GetLatestSummaryByAccountType(string accountType)
        {
            return await context.AccountSummaryReports
                .Where(g => g.accountType == accountType)
                .FirstOrDefaultAsync();
        }

        public async Task<List<AccountSummaryReport>> GetTopAccountsByBalance(int topCount = 10)
        {
            return await context.AccountSummaryReports
                .OrderByDescending(g => g.totalBalance)
                .Take(topCount)
                .ToListAsync();
        }
    }
}