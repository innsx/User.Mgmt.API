using MailKit.Net.Smtp;
using MimeKit;
using User.Mgmt.Service.Models;

namespace User.Mgmt.Service.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfiguration _emailConfig;

        public EmailService(EmailConfiguration emailConfig)
        {
            _emailConfig = emailConfig;
        }

        public Task<bool> ComposeNSendEmailsAsync(Message message)
        {
            var composeMimeMessage = ComposeEmail(message);

            if (composeMimeMessage is not null)
            {
                var isSendSuccessful = Send(composeMimeMessage);
                 
                if (isSendSuccessful is true)
                {
                    return Task.FromResult(true);
                }
            }  
            return Task.FromResult(false);
        }

        private MimeMessage ComposeEmail(Message message)
        {
            var mimeMessage = new MimeMessage();

            mimeMessage.From.Add(new MailboxAddress("email", _emailConfig.From));
            mimeMessage.To.AddRange(message.To);
            mimeMessage.Subject = message.Subject;
            mimeMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text)
            {
                Text = message.Content
            };

            return mimeMessage;
        }

        private bool Send(MimeMessage mimeMessage)
        {
            using var smtpClient = new SmtpClient();

            try
            {
                smtpClient.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
                smtpClient.AuthenticationMechanisms.Remove("XOAUTH2");
                smtpClient.Authenticate(_emailConfig.Username, _emailConfig.Password);

                smtpClient.Send(mimeMessage);

                return true;
            }
            catch
            {
                throw;
            }
            finally
            {
                smtpClient.Disconnect(true);
                smtpClient.Dispose();
            }
        }
    }
}
