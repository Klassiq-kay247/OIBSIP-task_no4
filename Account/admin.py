from django.contrib import admin
from Account.models import Account

class AccountAdmin(admin.ModelAdmin):
    list_display = ['username', 'email', 'bio']
    
admin.site.register(Account, AccountAdmin)


