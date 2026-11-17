import streamlit as st

all_pages = [
    st.Page("all_pages/1_landing_page.py", title="Home"),
    st.Page("all_pages/2_auth_page.py", title="Sign Up/Sign In"),
    st.Page("all_pages/6_admin_page.py", title="Administrador • Exportar datos"),
]

def main() -> None:
    pg = st.navigation(all_pages)
    pg.run()

if __name__ == "__main__":
    main()
