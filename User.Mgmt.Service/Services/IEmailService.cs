using User.Mgmt.Service.Models;

namespace User.Mgmt.Service.Services
{
    public interface IEmailService
    {
        public bool SendEmails(Message message);
    }
}
