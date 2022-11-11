from ninja import NinjaAPI
from apps.accounts.views import router as accounts_router
from apps.chat.views import router as chat_router
from . renderers import MyCustomRenderer

api = NinjaAPI(renderer=MyCustomRenderer(), csrf=True)

api.add_router("/accounts/", accounts_router)
api.add_router("/chat/", chat_router)
