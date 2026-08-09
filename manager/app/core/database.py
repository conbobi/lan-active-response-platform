from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.core.config import DATABASE_URL

# mở sẵn nhiều kết nối đến cơ sở dữ liệu để sử dụng trong các request
engine = create_async_engine(DATABASE_URL, echo=False)
#tạo ra các phiên bản session bất đồng bộ để tương tác với cơ sở dữ liệu
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with async_session() as session:
        yield session