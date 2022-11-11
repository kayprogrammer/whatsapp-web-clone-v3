from ninja import Router
from apps.common.custom_methods import CustomUserAuth

router = Router(auth=CustomUserAuth())

@router.get('/test')
def test(request):
    print(request.user)
    
    return {'test2': 'success'}
