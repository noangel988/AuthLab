from scalar_fastapi import get_scalar_api_reference, Layout, Theme
from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/docs", include_in_schema=False)
async def scalar_html(request: Request):
    return get_scalar_api_reference(
        openapi_url=request.app.openapi_url,
        title=request.app.title,
        layout=Layout.CLASSIC,
        theme=Theme.DEEP_SPACE,
        hide_models=True,
        hide_client_button=False,
        show_sidebar=True,
        hide_search=False,
        hide_dark_mode_toggle=False,
        with_default_fonts=True,
        expand_all_model_sections=False,
        expand_all_responses=False,
        integration="fastapi",
    )
