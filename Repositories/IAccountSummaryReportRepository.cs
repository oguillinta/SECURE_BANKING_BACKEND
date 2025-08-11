using ApiSecureBank.Entities;

namespace ApiSecureBank.Repositories
{
    public interface IAccountSummaryReportRepository
    {
        Task<int> Create(AccountSummaryReport accountSummaryReport);
        Task Delete(int id);
        Task<bool> Exist(int id);
        Task<List<AccountSummaryReport>> GetAll();
        Task<AccountSummaryReport?> GetById(int id);
        Task<List<AccountSummaryReport>> GetByAccountType(string accountType);
        Task Update(AccountSummaryReport accountSummaryReport);
        Task<List<AccountSummaryReport>> GetAccountsSummary();
        Task<AccountSummaryReport?> GetLatestSummaryByAccountType(string accountType);
        Task<List<AccountSummaryReport>> GetTopAccountsByBalance(int topCount = 10);
    }
}
