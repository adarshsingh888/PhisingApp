from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .predictUrl import predict_url
import json

@csrf_exempt  # Exempt CSRF for POST requests
def predict(request):
    if request.method == 'POST':
        # Get the URL from the POST request body
        data = json.loads(request.body)
        url = data.get('url')

        if not url:
            return JsonResponse({'error': 'URL is required'}, status=400)

        # Get the prediction result
        result = predict_url(url)
        return JsonResponse({'result': result})

    return JsonResponse({'error': 'Invalid request method'}, status=405)
