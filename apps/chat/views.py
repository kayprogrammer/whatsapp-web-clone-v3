from ninja import Router
router = Router()
from apps.common.custom_methods import CustomUserAuth

@router.get('/test', auth=CustomUserAuth())
def test(request):
    print(request.user)
    
    return {'test2': 'success'}
