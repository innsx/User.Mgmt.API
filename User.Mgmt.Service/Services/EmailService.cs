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

        public bool SendEmails(Message message)
        {
            var emailMessage = CreateEmailMessage(message);

            if (emailMessage != null)
            {
                var isSendSuccessful = Send(emailMessage);

                if (isSendSuccessful is true)
                {
                    return true;
                }
            }  
            return false;
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();

            emailMessage.From.Add(new MailboxAddress("email", _emailConfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text)
            {
                Text = message.Content
            };

            return emailMessage;
        }

        private bool Send(MimeMessage mailMessage)
        {
            using var smtpClient = new SmtpClient();

            try
            {
                smtpClient.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
                smtpClient.AuthenticationMechanisms.Remove("XOAUTH2");
                smtpClient.Authenticate(_emailConfig.Username, _emailConfig.Password);

                smtpClient.Send(mailMessage);

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
