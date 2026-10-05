from pprint import pprint

from soc_multi_agent.rag.database import (
    get_rag_schema_status,
    initialize_rag_schema,
)


def main() -> None:
    print("Initializing RAG database schema...")

    initialize_rag_schema()

    print("RAG database schema initialized.")
    print()

    status = get_rag_schema_status()

    pprint(status)


if __name__ == "__main__":
    main()
